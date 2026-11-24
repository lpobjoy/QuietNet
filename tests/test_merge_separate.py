"""Checks for Merge and Separate: the owner saying two entries are one device, or that one of a
device's hardware addresses is a device of its own after all. Neither ever happens automatically,
and neither happens on the first ask: the answer is a preview of what would apply to each hardware
address afterwards, and only a second request that sends the preview's marker back changes
anything. Also the dashboard page's parts for one card per device, the address list, the pickers
by device name and the "Same device?" question.

Run with:  python3 -m unittest discover tests

Standard library only. The neighbour table is always a stand-in passed to the looks (or patched
for the API), so nothing reads the real network; the page is read as text, never run in a browser.
"""
import os
import re
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_quietnet import server  # noqa: E402
from test_dashboard_api import Api  # noqa: E402
from test_device_moves import (Setup, answered_blocked, blocked_for, fresh, stale,  # noqa: E402
                               PI, PI_MAC, ROUTER, ROUTER_MAC, OLD, NEW, OTHER, PHONE, LAPTOP, PRIVATE, TV,
                               EXTENDER, V6_A)

CABLE, WIFI = LAPTOP, TV               # the two network cards of one laptop
AT_CABLE, AT_WIFI = OLD, NEW           # where each is on the home network


def tables():
    """Everything in the database a merge or a separation could touch, to show nothing changed."""
    names = ("device", "device_hw", "address_use", "group_member", "live_cut", "device_follow", "internet_off",
             "service_blocks", "schedules", "events", "queries", "rule_conflict")
    return {name: sorted(server.sql("SELECT * FROM %s" % name), key=repr) for name in names}


class TwoDevices(Api, Setup):
    """Shared steps: a laptop seen on its cable (at AT_CABLE) and on its Wi-Fi (at AT_WIFI), which
    QuietNet takes for two devices, as it must: nothing is merged automatically."""

    def setUp(self):
        super().setUp()
        self.start_clean()
        self.table = {AT_CABLE: fresh(CABLE), AT_WIFI: fresh(WIFI)}
        self.look(self.table)
        self.cable, self.wifi = self.number(CABLE), self.number(WIFI)
        # The API reads the neighbour table for a look straight after a separation: a stand-in.
        seen = mock.patch.object(server, "neighbour_table", side_effect=self.live_table)
        seen.start()
        self.addCleanup(seen.stop)

    def live_table(self):
        """The stand-in neighbour table, with this computer and the router in it."""
        full = {PI: fresh(PI_MAC), ROUTER: fresh(ROUTER_MAC)}
        full.update(self.table)
        return full

    def preview(self, device, other):
        """The preview of merging `other` into `device`."""
        return self.ok("/api/merge", {"device": device, "with": other})["preview"]

    def merge(self, device, other):
        """Ask, then confirm with the marker shown. Returns the merged device's number."""
        marker = self.preview(device, other)["marker"]
        return self.ok("/api/merge", {"device": device, "with": other, "seen": marker})["device"]

    def split_preview(self, device, mac):
        return self.ok("/api/separate", {"device": device, "mac": mac})["preview"]

    def split(self, device, mac, rules):
        """Ask, then confirm with the marker shown and the answer about rules. Returns the new device's number."""
        marker = self.split_preview(device, mac)["marker"]
        return self.ok("/api/separate", {"device": device, "mac": mac, "rules": rules, "seen": marker})["device"]

    def applies(self, preview, mac):
        """{rule in plain words: is it new for this hardware address?} from a merge preview."""
        entry = next(h for h in preview["hardware"] if h["mac"] == mac)
        return {x["text"]: x["new"] for x in entry["applies"]}

    def stops(self, preview, mac):
        return next(h for h in preview["hardware"] if h["mac"] == mac)["stops"]

    def file_lookup(self, address, name, device, ago=60):
        """Put one lookup into the history, filed against a device."""
        with server.db_lock:
            server.save_history([(time.time() - ago, address, name, 0, device, address)])


class MergeIsShownFirst(TwoDevices):
    """Asking to merge answers with what would apply, and changes nothing."""

    def test_asking_to_merge_changes_nothing(self):
        server.set_service_block("dev:%d" % self.wifi, "youtube", True)
        before, memory = tables(), (dict(server.S.hw_device), dict(server.S.svc_blocks), dict(server.S.given))
        self.preview(self.cable, self.wifi)
        self.assertEqual(tables(), before)
        self.assertEqual((server.S.hw_device, server.S.svc_blocks, server.S.given), memory)

    def test_the_preview_lists_every_hardware_address_of_both_devices(self):
        preview = self.preview(self.cable, self.wifi)
        self.assertEqual([(h["mac"], h["label"]) for h in preview["hardware"]], [(CABLE, AT_CABLE), (WIFI, AT_WIFI)])

    def test_the_preview_says_which_rules_would_apply_to_each_hardware_address(self):
        server.set_internet_off("dev:%d" % self.cable, True)
        server.set_service_block("dev:%d" % self.wifi, "youtube", True)
        server.set_live_cut(self.wifi, True)
        self.schedule(scope="dev:%d" % self.wifi)
        preview = self.preview(self.cable, self.wifi)
        everything = ["Internet switched off", "YouTube blocked",
                      'The "Bedtime" schedule (all internet off, 21:00 to 07:00)', "Cut live connections"]
        self.assertEqual(list(self.applies(preview, CABLE)), everything)
        self.assertEqual(list(self.applies(preview, WIFI)), everything)

    def test_the_preview_marks_the_rules_that_are_new_for_each_hardware_address(self):
        server.set_internet_off("dev:%d" % self.cable, True)
        server.set_service_block("dev:%d" % self.wifi, "youtube", True)
        preview = self.preview(self.cable, self.wifi)
        self.assertEqual(self.applies(preview, CABLE), {"Internet switched off": False, "YouTube blocked": True})
        self.assertEqual(self.applies(preview, WIFI), {"Internet switched off": True, "YouTube blocked": False})

    def test_the_preview_shows_what_a_group_brings_to_the_other_hardware_address(self):
        kids = self.make_group("Kids", "tiktok")
        server.set_internet_off("group:%d" % kids, True)
        server.set_device_group(self.cable, kids)
        preview = self.preview(self.cable, self.wifi)
        self.assertEqual(self.applies(preview, WIFI), {"In the Kids group": True,
                                                       "Internet switched off for the Kids group": True,
                                                       "TikTok blocked for the Kids group": True})
        self.assertEqual(preview["group"], kids)
        self.assertEqual(preview["group_name"], "Kids")

    def test_the_preview_says_which_rules_stop_when_a_group_gives_way(self):
        kids, adults = self.make_group("Kids", "tiktok"), self.make_group("Adults")
        server.set_device_group(self.cable, adults)
        server.set_device_group(self.wifi, kids)
        preview = self.preview(self.cable, self.wifi)
        self.assertEqual(self.stops(preview, WIFI), ["In the Kids group", "TikTok blocked for the Kids group"])
        self.assertEqual(self.stops(preview, CABLE), [])
        self.assertIn("It will no longer be in the Kids group, so what is blocked or scheduled for that group stops "
                      "applying to it.", preview["notes"])

    def test_the_preview_says_what_the_merged_device_will_be_called_and_which_name_goes(self):
        server.set_device_name(self.cable, "Sam's laptop")
        server.set_device_name(self.wifi, "Unknown laptop")
        preview = self.preview(self.cable, self.wifi)
        self.assertEqual(preview["name"], "Sam's laptop")
        self.assertIn('The merged device will be called "Sam\'s laptop". The name "Unknown laptop" is not kept.',
                      preview["notes"])

    def test_the_preview_says_the_histories_join_and_how_to_undo_it(self):
        notes = self.preview(self.cable, self.wifi)["notes"]
        self.assertIn("The history of both becomes one history. Every internet switch, blocked service and schedule "
                      "either has is kept.", notes)
        self.assertIn("You can undo this with Separate on the device's page. The history then stays with this device.",
                      notes)

    def test_a_schedule_that_is_switched_off_is_shown_as_not_in_use(self):
        schedule = self.schedule(scope="dev:%d" % self.wifi)
        self.ok("/api/schedule-enable", {"id": schedule["id"], "on": False})
        self.assertIn('The "Bedtime" schedule (all internet off, 21:00 to 07:00, not in use)',
                      self.applies(self.preview(self.cable, self.wifi), CABLE))

    def test_rules_for_the_whole_house_are_left_out_of_the_preview(self):
        server.set_service_block("all", "youtube", True)
        self.assertEqual(self.applies(self.preview(self.cable, self.wifi), CABLE), {})

    def test_the_marker_changes_when_a_rule_changes(self):
        first = self.preview(self.cable, self.wifi)["marker"]
        self.assertEqual(self.preview(self.cable, self.wifi)["marker"], first)
        server.set_service_block("dev:%d" % self.wifi, "youtube", True)
        self.assertNotEqual(self.preview(self.cable, self.wifi)["marker"], first)


class MergeIsDoneOnlyWhenConfirmed(TwoDevices):
    """The merge itself needs the marker of the preview the owner was shown."""

    def test_sending_the_markers_back_merges_the_two(self):
        kept = self.merge(self.cable, self.wifi)
        self.assertEqual(kept, self.cable)
        self.assertEqual(server.S.hw_device[WIFI], self.cable)
        self.assertEqual(server.sql("SELECT mac FROM device_hw WHERE device=? ORDER BY mac", (self.cable,)),
                         sorted([(CABLE,), (WIFI,)]))
        self.assertEqual(server.sql("SELECT id FROM device WHERE id=?", (self.wifi,)), [])

    def test_the_devices_may_be_named_by_numbers_written_as_text(self):
        # The page keeps a device's number as text.
        device, other = str(self.cable), str(self.wifi)
        marker = self.ok("/api/merge", {"device": device, "with": other})["preview"]["marker"]
        self.assertEqual(self.ok("/api/merge", {"device": device, "with": other, "seen": marker})["device"], self.cable)

    def test_a_wrong_marker_changes_nothing(self):
        before = tables()
        status, out = self.post("/api/merge", {"device": self.cable, "with": self.wifi, "seen": "not-the-marker"})
        self.assertEqual((status, out["error"]), (409, server.PREVIEW_CHANGED))
        self.assertEqual(tables(), before)

    def test_a_marker_that_is_not_text_changes_nothing(self):
        before = tables()
        for seen in (None, True, 7, ["x"], {"a": 1}):
            status, _ = self.post("/api/merge", {"device": self.cable, "with": self.wifi, "seen": seen})
            self.assertEqual(status, 409, seen)
        self.assertEqual(tables(), before)

    def test_a_merge_is_refused_when_a_rule_changed_since_the_preview_was_shown(self):
        marker = self.preview(self.cable, self.wifi)["marker"]
        server.set_internet_off("dev:%d" % self.wifi, True)             # changed after the owner read the preview
        status, out = self.post("/api/merge", {"device": self.cable, "with": self.wifi, "seen": marker})
        self.assertEqual((status, out["error"]), (409, server.PREVIEW_CHANGED))
        self.assertIn(self.wifi, server.S.device_kind)
        self.assertEqual(server.S.off, {"dev:%d" % self.wifi})

    def test_the_merged_device_keeps_every_rule_either_had(self):
        kids = self.make_group("Kids")
        server.set_device_group(self.wifi, kids)
        server.set_internet_off("dev:%d" % self.wifi, True)
        server.set_service_block("dev:%d" % self.wifi, "tiktok", True)
        server.set_service_block("dev:%d" % self.cable, "youtube", True)
        server.set_live_cut(self.wifi, True)
        self.schedule(scope="dev:%d" % self.wifi)
        self.merge(self.cable, self.wifi)
        scope = "dev:%d" % self.cable
        self.assertEqual((server.S.dev_group, server.S.off, server.S.svc_blocks, server.S.enforced),
                         ({self.cable: kids}, {scope}, {scope: {"tiktok", "youtube"}}, {self.cable}))
        self.assertEqual([x["scope"] for x in server.S.schedules], [scope])

    def test_what_was_shown_is_what_applies_afterwards(self):
        kids = self.make_group("Kids", "tiktok")
        server.set_device_group(self.wifi, kids)
        server.set_service_block("dev:%d" % self.cable, "youtube", True)
        shown = list(self.applies(self.preview(self.cable, self.wifi), CABLE))
        self.merge(self.cable, self.wifi)
        self.assertEqual(list(server.rules_now(self.cable).values()), shown)

    def test_both_addresses_get_the_rules_at_once(self):
        server.set_service_block("dev:%d" % self.cable, "youtube", True)
        self.assertFalse(answered_blocked(AT_WIFI))
        self.merge(self.cable, self.wifi)
        self.assertTrue(answered_blocked(AT_CABLE))
        self.assertTrue(answered_blocked(AT_WIFI))

    def test_the_device_merged_into_keeps_its_name_and_its_group(self):
        kids, adults = self.make_group("Kids"), self.make_group("Adults")
        server.set_device_name(self.cable, "Sam's laptop")
        server.set_device_name(self.wifi, "Unknown laptop")
        server.set_device_group(self.cable, adults)
        server.set_device_group(self.wifi, kids)
        self.merge(self.cable, self.wifi)
        self.assertEqual((server.S.given, server.S.dev_group), ({self.cable: "Sam's laptop"}, {self.cable: adults}))

    def test_two_devices_with_no_rules_at_all_can_be_merged(self):
        self.assertEqual(self.merge(self.cable, self.wifi), self.cable)
        self.assertEqual(sorted(server.hardware_of(self.cable)), sorted([CABLE, WIFI]))

    def test_a_device_with_rules_of_its_own_can_be_merged_once_the_owner_has_seen_the_result(self):
        # The older "same device" call refuses this, because it could not show what would apply.
        server.set_service_block("dev:%d" % self.cable, "youtube", True)
        server.set_service_block("dev:%d" % self.wifi, "tiktok", True)
        self.assertIn("Merge with", server.same_device_by_hand(self.wifi, self.cable))
        self.merge(self.cable, self.wifi)
        self.assertEqual(server.S.svc_blocks, {"dev:%d" % self.cable: {"tiktok", "youtube"}})

    def test_the_merged_device_has_one_history(self):
        self.file_lookup(AT_CABLE, "www.bbc.co.uk", self.cable)
        self.file_lookup(AT_WIFI, "www.itv.com", self.wifi)
        self.merge(self.cable, self.wifi)
        self.assertEqual(server.sql("SELECT domain, device FROM queries ORDER BY domain"),
                         [("www.bbc.co.uk", self.cable), ("www.itv.com", self.cable)])

    def test_the_merged_device_is_one_card_with_both_addresses_and_both_hardware_addresses(self):
        self.merge(self.cable, self.wifi)
        cards = [d for d in self.get("/api/devices?all=1")[1] if d["kind"] == "hw"]
        self.assertEqual(len(cards), 1)
        self.assertEqual(sorted(cards[0]["macs"]), sorted([CABLE, WIFI]))
        self.assertEqual(sorted(a["address"] for a in cards[0]["addresses"] if a["now"]), sorted([AT_CABLE, AT_WIFI]))

    def test_the_merged_device_is_steered_at_each_hardware_address(self):
        self.merge(self.cable, self.wifi)
        server.set_live_cut(self.cable, True)
        plan = self.plan({AT_CABLE: fresh(CABLE), AT_WIFI: fresh(WIFI)})
        self.assertEqual({ip: rule["mac"] for ip, rule in plan.items()}, {AT_CABLE: CABLE, AT_WIFI: WIFI})

    def test_the_merge_lasts_through_a_restart(self):
        server.set_service_block("dev:%d" % self.wifi, "youtube", True)
        self.merge(self.cable, self.wifi)
        server.init_db()
        self.look(self.table, later=60)
        self.assertEqual(server.S.hw_device[WIFI], self.cable)
        self.assertTrue(blocked_for(AT_CABLE))

    def test_the_merge_is_noted_in_plain_english(self):
        server.set_device_name(self.cable, "Sam's laptop")
        self.merge(self.cable, self.wifi)
        self.assertIn("You merged %s into Sam's laptop, so they are now one device with one set of rules." % AT_WIFI,
                      self.events())

    def test_nothing_is_ever_merged_without_being_asked(self):
        # Same name, same group, seen for hours: still two devices until the owner says so.
        server.set_device_name(self.cable, "Laptop")
        server.set_device_name(self.wifi, "Laptop")
        for minute in range(1, 30):
            self.look(self.table, later=60 * minute)
        self.assertNotEqual(self.number(CABLE), self.number(WIFI))


class WhatCannotBeMerged(TwoDevices):
    """Refusals, each in words for the owner, and each leaving everything as it was."""

    def refused(self, device, other):
        before = tables()
        status, out = self.post("/api/merge", {"device": device, "with": other})
        self.assertEqual(status, 400, out)
        self.assertEqual(tables(), before)
        return out["error"]

    def test_this_computer_and_the_router_are_never_merged(self):
        for fixed in (server.S.pi_device, server.S.hub_device):
            self.assertEqual(self.refused(fixed, self.cable),
                             "This computer and the router can't be merged with another device.")
            self.assertEqual(self.refused(self.cable, fixed),
                             "This computer and the router can't be merged with another device.")

    def test_a_device_is_not_merged_with_itself(self):
        self.assertEqual(self.refused(self.cable, self.cable), "Choose two different devices to merge.")

    def test_a_device_quietnet_does_not_know_is_refused(self):
        self.assertEqual(self.refused(self.cable, 999999), server.UNKNOWN_DEVICE)
        self.assertEqual(self.refused("x", self.cable), server.UNKNOWN_DEVICE)
        self.assertEqual(self.refused(None, [1]), server.UNKNOWN_DEVICE)

    def test_two_numbers_with_no_hardware_address_are_not_merged(self):
        first, second = self.device("192.168.1.90"), self.device("192.168.1.91")
        self.assertIn("only by their numbers", self.refused(first, second))

    def test_a_number_behind_a_range_extender_is_not_merged(self):
        table = {AT_CABLE: fresh(CABLE), OTHER: fresh(EXTENDER), "192.168.1.81": fresh(EXTENDER)}
        for minute in range(1, 1 + server.SHARED_AFTER):
            self.look(table, later=60 * minute)
        behind = server.S.addr_only[OTHER]
        self.assertIn("behind a Wi-Fi range extender", self.refused(self.cable, behind))
        self.assertIn("behind a Wi-Fi range extender", self.refused(behind, self.cable))

    def test_rules_waiting_for_the_owners_decision_are_not_merged(self):
        with server.rule_map_lock:
            server.S.set_aside = frozenset({self.wifi})
        self.addCleanup(setattr, server.S, "set_aside", frozenset())
        self.assertIn("waiting for your decision", self.refused(self.cable, self.wifi))

    def test_one_device_is_not_given_more_hardware_addresses_than_quietnet_keeps(self):
        with mock.patch.object(server, "MAX_HARDWARE_ADDRESSES", 1):
            self.assertIn("more hardware addresses than QuietNet keeps", self.refused(self.cable, self.wifi))

    def test_merging_waits_until_an_older_households_data_has_been_moved(self):
        server.S.devices_ready = False
        self.addCleanup(setattr, server.S, "devices_ready", True)
        status, out = self.post("/api/merge", {"device": self.cable, "with": self.wifi})
        self.assertEqual((status, out["error"]), (400, server.STILL_MOVING))


class ADeviceKnownOnlyByItsNumber(TwoDevices):
    """Rules kept under a number alone can be merged into the device that has a hardware address."""

    def setUp(self):
        super().setUp()
        self.held = self.device("192.168.1.90")
        server.set_device_name(self.held, "Den TV")
        server.set_service_block("dev:%d" % self.held, "youtube", True)

    def test_the_device_with_a_hardware_address_is_the_one_kept(self):
        self.assertEqual(self.preview(self.held, self.cable)["keep"], self.cable)
        self.assertEqual(self.merge(self.held, self.cable), self.cable)
        self.assertNotIn(self.held, server.S.device_kind)
        self.assertEqual(server.S.device_kind[self.cable], "hw")

    def test_its_name_and_rules_go_to_the_merged_device(self):
        server.set_device_name(self.cable, "Laptop")
        self.merge(self.held, self.cable)                              # merged INTO the number's entry: its name wins
        self.assertEqual(server.S.given, {self.cable: "Den TV"})
        self.assertEqual(server.S.svc_blocks, {"dev:%d" % self.cable: {"youtube"}})

    def test_the_preview_says_what_becomes_of_the_number(self):
        notes = self.preview(self.cable, self.held)["notes"]
        self.assertIn("QuietNet knows Den TV only by its number. Its rules and history go to the merged device; "
                      "anything that still looks things up from that number afterwards will show as a separate "
                      "entry again.", notes)

    def test_only_hardware_addresses_are_listed_since_a_number_has_none(self):
        preview = self.preview(self.cable, self.held)
        self.assertEqual([h["mac"] for h in preview["hardware"]], [CABLE])
        self.assertEqual(self.applies(preview, CABLE), {"YouTube blocked": True})


class TheNewDeviceGroupGivesWay(TwoDevices):
    """A group QuietNet itself put a device in, as a new device, does not stick to a device the
    owner says is one already known."""

    def setUp(self):
        super().setUp()
        self.guests = self.make_group("Guests", "tiktok")
        server.set_new_device_group(self.guests)
        self.addCleanup(server.set_new_device_group, None)
        self.look(dict(self.table, **{OTHER: fresh(PHONE)}), later=60)   # a newcomer, put in Guests
        self.newcomer = self.number(PHONE)
        self.assertEqual(server.S.dev_group, {self.newcomer: self.guests})

    def test_merging_a_newcomer_into_a_known_device_drops_the_new_device_group(self):
        preview = self.preview(self.cable, self.newcomer)
        self.assertIsNone(preview["group"])
        self.assertEqual(self.stops(preview, PHONE), ["In the Guests group", "TikTok blocked for the Guests group"])
        self.merge(self.cable, self.newcomer)
        self.assertEqual(server.S.dev_group, {})
        self.assertFalse(blocked_for(OTHER, "tiktok.com"))

    def test_it_gives_way_whichever_of_the_two_the_owner_started_from(self):
        kids = self.make_group("Kids")
        server.set_device_group(self.cable, kids)
        self.assertEqual(self.preview(self.newcomer, self.cable)["group"], kids)
        self.merge(self.newcomer, self.cable)
        self.assertEqual(server.S.dev_group, {self.newcomer: kids})

    def test_a_group_the_owner_chose_does_not_give_way_like_that(self):
        server.set_device_group(self.newcomer, self.guests)             # now the owner's own choice
        self.assertEqual(self.preview(self.cable, self.newcomer)["group"], self.guests)
        self.merge(self.cable, self.newcomer)
        self.assertEqual(server.S.dev_group, {self.cable: self.guests})


class TheSameDeviceQuestion(Api, Setup):
    """A phone back with a new private Wi-Fi address is held to its old rules and the owner is
    asked. "Yes" goes through the same preview, and still nothing is merged until it is confirmed."""

    def setUp(self):
        super().setUp()
        self.start_clean()
        self.look({OLD: PHONE})
        self.phone = self.give_rules(PHONE)
        self.look({OLD: PRIVATE}, later=60)
        self.newcomer = self.number(PRIVATE)

    def test_the_question_alone_merges_nothing(self):
        self.assertEqual(server.S.provisional, {self.newcomer: self.phone})
        self.ok("/api/merge", {"device": self.phone, "with": self.newcomer})
        self.assertNotEqual(self.number(PRIVATE), self.phone)

    def test_rules_already_applied_for_now_are_not_shown_as_new(self):
        preview = self.ok("/api/merge", {"device": self.phone, "with": self.newcomer})["preview"]
        entry = next(h for h in preview["hardware"] if h["mac"] == PRIVATE)
        self.assertEqual(entry["applies"], [{"text": "YouTube blocked", "new": False}])
        self.assertEqual(entry["stops"], [])

    def test_yes_through_the_preview_joins_the_two_and_closes_the_question(self):
        marker = self.ok("/api/merge", {"device": self.phone, "with": self.newcomer})["preview"]["marker"]
        out = self.ok("/api/merge", {"device": self.phone, "with": self.newcomer, "seen": marker})
        self.assertEqual(out["device"], self.phone)
        self.assertEqual(server.S.hw_device[PRIVATE], self.phone)
        self.assertEqual(server.S.provisional, {})
        self.look({OLD: PRIVATE}, later=120)
        self.assertEqual(server.S.device_notices, [])
        self.assertTrue(blocked_for(OLD))

    def test_the_phone_keeps_its_name_when_the_newcomer_is_merged_into_it(self):
        marker = self.ok("/api/merge", {"device": self.phone, "with": self.newcomer})["preview"]["marker"]
        self.ok("/api/merge", {"device": self.phone, "with": self.newcomer, "seen": marker})
        self.assertEqual(server.S.given, {self.phone: "Wilf's iPad"})

    def test_the_older_call_still_answers_the_question_for_pages_written_before_merge(self):
        self.ok("/api/move-rules", {"from": OLD, "to": OLD})
        self.assertEqual(server.S.hw_device[PRIVATE], self.phone)


class RulesKeptUnderANumber(Api, Setup):
    """Rules set for an address before QuietNet could tell which device has it. The device then
    seen there is given them for now, and "yes, they are this device's" goes through the preview."""

    def setUp(self):
        super().setUp()
        self.start_clean()
        self.ok("/api/service-block", {"scope": "device:" + OLD, "service": "youtube", "on": True})
        self.held = server.S.addr_only[OLD]
        self.look({OLD: PHONE}, later=60)
        self.phone = self.number(PHONE)

    def test_yes_through_the_preview_gives_the_rules_to_the_device_itself(self):
        self.assertEqual(server.S.provisional, {self.phone: self.held})
        preview = self.ok("/api/merge", {"device": self.held, "with": self.phone})["preview"]
        self.assertEqual(preview["keep"], self.phone)
        self.assertEqual(preview["hardware"], [{"mac": PHONE, "label": OLD, "stops": [],
                                                "applies": [{"text": "YouTube blocked", "new": False}]}])
        self.ok("/api/merge", {"device": self.held, "with": self.phone, "seen": preview["marker"]})
        self.assertEqual(server.S.svc_blocks, {"dev:%d" % self.phone: {"youtube"}})
        self.assertNotIn(self.held, server.S.device_kind)
        self.look({NEW: PHONE}, later=120)                          # and they go with it from now on
        self.assertTrue(blocked_for(NEW))
        self.assertFalse(blocked_for(OLD))


class SeparateIsShownFirst(TwoDevices):
    """Asking to separate answers with what would happen, and changes nothing."""

    def setUp(self):
        super().setUp()
        server.set_device_name(self.cable, "Sam's laptop")
        self.kids = self.make_group("Kids", "tiktok")
        server.set_device_group(self.cable, self.kids)
        server.set_service_block("dev:%d" % self.cable, "youtube", True)
        self.merged = self.merge(self.cable, self.wifi)

    def test_asking_to_separate_changes_nothing(self):
        before = tables()
        self.split_preview(self.merged, WIFI)
        self.assertEqual(tables(), before)
        self.assertEqual(server.S.hw_device[WIFI], self.merged)

    def test_the_preview_says_what_the_device_carries_and_what_stays(self):
        preview = self.split_preview(self.merged, WIFI)
        self.assertEqual((preview["mac"], preview["label"], preview["stays"]), (WIFI, "Sam's laptop", [CABLE]))
        self.assertEqual(preview["rules"], ["In the Kids group", "YouTube blocked", "TikTok blocked for the Kids group"])

    def test_the_preview_says_the_history_stays_with_the_device_it_was_merged_into(self):
        notes = self.split_preview(self.merged, WIFI)["notes"]
        self.assertIn("Its history so far stays with Sam's laptop. From now on what it looks up is kept under the new "
                      "device.", notes)
        self.assertIn("The hardware address %s becomes a device of its own again, with no name." % WIFI, notes)

    def test_separating_needs_the_owners_answer_about_the_rules(self):
        marker = self.split_preview(self.merged, WIFI)["marker"]
        before = tables()
        for rules in (None, "", "yes", True, ["copy"]):
            status, out = self.post("/api/separate", {"device": self.merged, "mac": WIFI, "seen": marker, "rules": rules})
            self.assertEqual((status, out["error"]), (400, "Please choose whether the rules go with it."), rules)
        self.assertEqual(tables(), before)

    def test_a_wrong_marker_changes_nothing(self):
        before = tables()
        status, out = self.post("/api/separate", {"device": self.merged, "mac": WIFI, "seen": "no", "rules": "none"})
        self.assertEqual((status, out["error"]), (409, server.PREVIEW_CHANGED))
        self.assertEqual(tables(), before)

    def test_a_separation_is_refused_when_a_rule_changed_since_the_preview_was_shown(self):
        marker = self.split_preview(self.merged, WIFI)["marker"]
        server.set_internet_off("dev:%d" % self.merged, True)
        status, _ = self.post("/api/separate", {"device": self.merged, "mac": WIFI, "seen": marker, "rules": "copy"})
        self.assertEqual(status, 409)
        self.assertEqual(server.S.hw_device[WIFI], self.merged)

    def test_a_device_with_one_hardware_address_has_nothing_to_separate(self):
        self.look(dict(self.table, **{OTHER: fresh(PHONE)}), later=60)
        status, out = self.post("/api/separate", {"device": self.number(PHONE), "mac": PHONE})
        self.assertEqual((status, out["error"]),
                         (400, "This device has only one hardware address, so there is nothing to separate."))

    def test_a_hardware_address_of_another_device_is_refused(self):
        self.look(dict(self.table, **{OTHER: fresh(PHONE)}), later=60)
        status, out = self.post("/api/separate", {"device": self.merged, "mac": PHONE})
        self.assertEqual((status, out["error"]), (400, "That hardware address does not belong to this device."))

    def test_something_that_is_not_a_hardware_address_is_refused(self):
        for mac in ("", "not one", None, 7, "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            status, out = self.post("/api/separate", {"device": self.merged, "mac": mac})
            self.assertEqual((status, out["error"]), (400, "That is not a hardware address."), mac)

    def test_this_computer_and_the_router_have_nothing_to_separate(self):
        for fixed in (server.S.pi_device, server.S.hub_device):
            status, _ = self.post("/api/separate", {"device": fixed, "mac": ROUTER_MAC})
            self.assertEqual(status, 400)


class SeparatedWithNoRules(TwoDevices):
    """"Separate, with no rules": the hardware address is a device of its own, carrying nothing."""

    def setUp(self):
        super().setUp()
        server.set_device_name(self.cable, "Sam's laptop")
        self.kids = self.make_group("Kids", "tiktok")
        server.set_device_group(self.cable, self.kids)
        server.set_service_block("dev:%d" % self.cable, "youtube", True)
        server.set_live_cut(self.cable, True)
        self.merged = self.merge(self.cable, self.wifi)
        self.file_lookup(AT_WIFI, "www.itv.com", self.merged)
        self.new = self.split(self.merged, WIFI, "none")

    def test_the_hardware_address_is_a_device_of_its_own_again(self):
        self.assertNotIn(self.new, (self.merged, self.wifi))               # a new number, never one used before
        self.assertEqual(server.S.hw_device, dict(server.S.hw_device, **{WIFI: self.new, CABLE: self.merged}))
        self.assertEqual(server.S.device_kind[self.new], "hw")
        self.assertEqual(server.sql("SELECT device FROM device_hw WHERE mac=?", (WIFI,)), [(self.new,)])

    def test_it_carries_nothing_of_its_own(self):
        self.assertFalse(server.own_rules(self.new))
        self.assertNotIn(self.new, server.S.dev_group)
        self.assertNotIn(self.new, server.S.enforced)

    def test_its_lookups_stop_getting_the_other_devices_rules_at_once(self):
        self.assertFalse(answered_blocked(AT_WIFI))
        self.assertFalse(blocked_for(AT_WIFI, "tiktok.com"))
        self.assertEqual(server.S.addr_device[AT_WIFI], self.new)

    def test_the_device_it_left_keeps_its_name_group_and_rules(self):
        self.assertEqual(server.S.given, {self.merged: "Sam's laptop"})
        self.assertEqual(server.S.dev_group, {self.merged: self.kids})
        self.assertTrue(answered_blocked(AT_CABLE))
        self.assertTrue(blocked_for(AT_CABLE, "tiktok.com"))
        self.assertEqual(server.S.enforced, {self.merged})

    def test_the_history_stays_with_the_device_it_was_merged_into(self):
        self.assertEqual(server.sql("SELECT domain, device FROM queries"), [("www.itv.com", self.merged)])

    def test_what_it_looks_up_from_now_on_is_kept_under_the_new_device(self):
        self.assertEqual(server.device_of_lookup(AT_WIFI, AT_WIFI), self.new)

    def test_it_is_no_longer_steered_for_the_other_devices_cut(self):
        plan = self.plan({AT_CABLE: fresh(CABLE), AT_WIFI: fresh(WIFI)})
        self.assertEqual({ip: rule["mac"] for ip, rule in plan.items()}, {AT_CABLE: CABLE})

    def test_it_shows_as_a_card_of_its_own(self):
        cards = {d["id"]: d for d in self.get("/api/devices?all=1")[1]}
        self.assertEqual(cards[self.new]["macs"], [WIFI])
        self.assertEqual(cards[self.new]["ip"], AT_WIFI)
        self.assertEqual(cards[self.merged]["macs"], [CABLE])
        self.assertEqual(cards[self.new]["name"], "")

    def test_the_separation_is_noted_in_plain_english(self):
        self.assertIn("You separated the hardware address %s from Sam's laptop. It is a device of its own again, with "
                      "no rules of its own. Its history so far stays with Sam's laptop." % WIFI, self.events())

    def test_the_separation_lasts_through_a_restart(self):
        server.init_db()
        self.look(self.table, later=60)
        self.assertEqual((server.S.hw_device[WIFI], server.S.hw_device[CABLE]), (self.new, self.merged))
        self.assertFalse(blocked_for(AT_WIFI))
        self.assertTrue(blocked_for(AT_CABLE))

    def test_the_two_can_be_merged_again(self):
        self.assertEqual(self.merge(self.merged, self.new), self.merged)
        self.assertEqual(server.S.hw_device[WIFI], self.merged)
        self.assertTrue(blocked_for(AT_WIFI))


class SeparatedWithTheSameRules(TwoDevices):
    """"Separate, with the same rules": the new device gets a copy of everything but the name."""

    def setUp(self):
        super().setUp()
        server.set_device_name(self.cable, "Sam's laptop")
        self.kids = self.make_group("Kids", "tiktok")
        server.set_device_group(self.cable, self.kids)
        server.set_internet_off("dev:%d" % self.cable, True)
        server.set_service_block("dev:%d" % self.cable, "youtube", True)
        server.set_live_cut(self.cable, True)
        self.schedule(scope="dev:%d" % self.cable)
        self.merged = self.merge(self.cable, self.wifi)
        self.new = self.split(self.merged, WIFI, "copy")

    def test_the_new_device_gets_a_copy_of_every_rule(self):
        scope = "dev:%d" % self.new
        self.assertEqual(server.S.dev_group[self.new], self.kids)
        self.assertIn(scope, server.S.off)
        self.assertEqual(server.S.svc_blocks[scope], {"youtube"})
        self.assertIn(self.new, server.S.enforced)
        self.assertEqual(sorted(x["scope"] for x in server.S.schedules), sorted([scope, "dev:%d" % self.merged]))

    def test_the_copy_is_in_the_database_too(self):
        server.init_db()
        scope = "dev:%d" % self.new
        self.assertEqual(server.S.dev_group[self.new], self.kids)
        self.assertIn(scope, server.S.off)
        self.assertEqual(server.S.svc_blocks[scope], {"youtube"})
        self.assertIn(self.new, server.S.enforced)
        self.assertEqual(len([x for x in server.S.schedules if x["scope"] == scope]), 1)

    def test_the_copied_group_counts_as_the_owners_own_choice(self):
        self.assertEqual(server.sql("SELECT auto FROM group_member WHERE device=?", (self.new,)), [(0,)])

    def test_the_new_device_gets_no_name(self):
        self.assertEqual(server.S.given, {self.merged: "Sam's laptop"})

    def test_both_devices_are_still_under_the_rules(self):
        self.assertTrue(answered_blocked(AT_WIFI))
        self.assertTrue(answered_blocked(AT_CABLE))

    def test_the_copies_are_separate_from_then_on(self):
        server.set_service_block("dev:%d" % self.new, "youtube", False)
        server.set_internet_off("dev:%d" % self.new, False)
        self.assertEqual(server.S.svc_blocks["dev:%d" % self.merged], {"youtube"})
        self.assertIn("dev:%d" % self.merged, server.S.off)

    def test_both_are_steered_each_at_its_own_address(self):
        plan = self.plan({AT_CABLE: fresh(CABLE), AT_WIFI: fresh(WIFI)})
        self.assertEqual({ip: rule["mac"] for ip, rule in plan.items()}, {AT_CABLE: CABLE, AT_WIFI: WIFI})

    def test_the_separation_is_noted_as_with_the_same_rules(self):
        self.assertTrue(any("It is a device of its own again, with the same rules." in t for t in self.events()))


class SeparatingTheHardwareAddressADeviceWasFirstKnownBy(TwoDevices):
    """The device's own record is keyed by the hardware address it was first seen with; that one
    can be separated too."""

    def setUp(self):
        super().setUp()
        server.set_device_name(self.cable, "Sam's laptop")
        self.merged = self.merge(self.cable, self.wifi)
        self.new = self.split(self.merged, CABLE, "none")

    def test_the_first_hardware_address_can_be_the_one_separated(self):
        self.assertEqual((server.S.hw_device[CABLE], server.S.hw_device[WIFI]), (self.new, self.merged))
        self.assertEqual(server.sql("SELECT id, key FROM device WHERE id IN (?,?) ORDER BY id", (self.merged, self.new)),
                         [(self.merged, "hw:" + WIFI), (self.new, "hw:" + CABLE)])

    def test_the_name_stays_with_the_device_not_the_hardware_address(self):
        self.assertEqual(server.S.given, {self.merged: "Sam's laptop"})

    def test_both_are_still_right_after_a_restart(self):
        server.init_db()
        self.look(self.table, later=60)
        self.assertEqual((self.number(CABLE), self.number(WIFI)), (self.new, self.merged))


class ASeparatedDeviceIsNotTakenForTheOther(Api, Setup):
    """After the owner separates two hardware addresses, QuietNet does not hold the separated one
    to the other's rules as "maybe the same device", and does not ask again."""

    def setUp(self):
        super().setUp()
        self.start_clean()
        self.look({OLD: fresh(PHONE)})
        self.phone = self.give_rules(PHONE)
        self.look({OLD: fresh(PRIVATE)}, later=60)               # back with a new private address: held to the rules
        self.newcomer = self.number(PRIVATE)
        marker = self.ok("/api/merge", {"device": self.phone, "with": self.newcomer})["preview"]["marker"]
        self.ok("/api/merge", {"device": self.phone, "with": self.newcomer, "seen": marker})
        table = {PI: fresh(PI_MAC), ROUTER: fresh(ROUTER_MAC), OLD: fresh(PRIVATE)}
        with mock.patch.object(server, "neighbour_table", return_value=table):
            marker = self.ok("/api/separate", {"device": self.phone, "mac": PRIVATE})["preview"]["marker"]
            self.new = self.ok("/api/separate", {"device": self.phone, "mac": PRIVATE, "rules": "none",
                                                 "seen": marker})["device"]

    def test_the_separated_device_is_not_held_to_the_other_devices_rules(self):
        self.assertEqual(server.S.provisional, {})
        self.assertFalse(blocked_for(OLD))

    def test_later_looks_do_not_start_the_question_again(self):
        for minute in range(2, 40):
            self.look({OLD: fresh(PRIVATE)}, later=60 * minute)
        self.assertEqual(server.S.provisional, {})
        self.assertEqual(server.S.device_notices, [])
        self.assertFalse(blocked_for(OLD))

    def test_that_they_are_different_devices_is_remembered_through_a_restart(self):
        server.init_db()
        self.assertIn((self.new, self.phone), server.S.not_same)
        self.look({OLD: fresh(PRIVATE)}, later=3600)
        self.assertEqual(server.S.provisional, {})

    def test_the_other_devices_rules_wait_for_it_to_come_back(self):
        self.look({OLD: fresh(PRIVATE), NEW: fresh(PHONE)}, later=120)
        self.assertTrue(blocked_for(NEW))
        self.assertFalse(blocked_for(OLD))


class WithoutALookStraightAfter(TwoDevices):
    """separate_by_hand without a neighbour table (not how the API calls it): the next look puts
    the addresses right."""

    def test_the_next_look_gives_the_separated_device_its_address(self):
        server.set_service_block("dev:%d" % self.cable, "youtube", True)
        merged = self.merge(self.cable, self.wifi)
        _, preview = server.separate_preview(merged, WIFI)
        error, new = server.separate_by_hand(merged, WIFI, "none", preview["marker"])
        self.assertIsNone(error)
        self.look(self.table, later=5)
        self.assertEqual(server.S.addr_device[AT_WIFI], new)
        self.assertFalse(blocked_for(AT_WIFI))
        self.assertTrue(blocked_for(AT_CABLE))

    def test_ipv6_addresses_follow_the_separated_hardware_address(self):
        merged = self.merge(self.cable, self.wifi)
        self.look6({V6_A: stale(WIFI)})
        self.assertEqual(server.S.addr_device[V6_A], merged)
        server.S.v6_table = {V6_A: stale(WIFI)}
        self.addCleanup(setattr, server.S, "v6_table", {})
        new = self.split(merged, WIFI, "none")
        self.assertEqual(server.S.addr_device[V6_A], new)


class TheDashboardPage(unittest.TestCase):
    """The page's parts for one card per device, the address list, pickers by name, Merge,
    Separate and the "Same device?" question. Reads the page's script only."""

    @classmethod
    def setUpClass(cls):
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(here, "static", "index.html"), encoding="utf-8") as f:
            cls.page = f.read()
        cls.script = cls.page[cls.page.index("const S = {"):cls.page.rindex("</script>")]
        cls.css = cls.page[cls.page.index("<style>"):cls.page.index("</style>")]

    def part(self, name):
        """The script of one function on the page: up to the next function, constant or comment
        that starts a line."""
        start = self.page.index("function %s(" % name)
        end = re.search(r"\n(?:async function |function |const |// |/\* )", self.page[start:])
        return self.page[start:start + end.start()]

    def action(self, name):
        """The script of one entry in the page's `actions`."""
        start = self.page.index("\n  async %s(" % name)
        return self.page[start:self.page.index("\n  },", start) + 5]

    # ----- one card per device

    def test_a_card_is_known_by_its_devices_number_or_failing_that_its_address(self):
        self.assertIn("const keyOf = d => Number.isInteger(d.id) ? 'd' + d.id : 'a' + d.ip;", self.page)
        self.assertIn("const cardOf = key => S.devices.find(d => keyOf(d) === key);", self.page)

    def test_cards_carry_the_device_not_an_address(self):
        self.assertIn('<button class="tile" data-act="open" data-device="${esc(keyOf(d))}">', self.part("viewHome"))
        self.assertIn("open(d){ S.device = d.device;", self.page)
        self.assertNotIn('data-act="open" data-ip=', self.page)

    def test_no_button_names_a_device_by_its_address_alone_any_more(self):
        # The two that still carry an address are answers an older Pi takes by address.
        carried = set(re.findall(r'data-act="(\w+)" data-ip=', self.page))
        self.assertEqual(carried, {"notsame", "samehere"})

    def test_a_device_with_no_address_now_is_shown_and_says_so(self):
        self.assertIn("api('/api/devices?all=1')", self.page)
        self.assertIn("(ip ? esc(ip) : 'Not on your network now')", self.part("addressWords"))

    def test_the_open_card_follows_an_address_that_has_just_been_given_a_number(self):
        rekey = self.part("rekey")
        self.assertIn("if(!S.device || cardOf(S.device)) return;", rekey)
        self.assertIn("if(d) S.device = keyOf(d);", rekey)

    def test_a_device_that_is_no_longer_listed_goes_back_to_the_list(self):
        self.assertIn("if(deviceId(S.device)){ S.device = null; return; }", self.part("rekey"))
        self.assertIn("devices.then(() => S.device ? ctl(scopeOf(S.device)) : null)", self.page)
        self.assertIn("if(!S.device) return null;", self.page)

    def test_the_card_counts_the_ipv6_addresses_and_leaves_the_list_to_the_device_page(self):
        words = self.part("addressWords")
        self.assertIn("(d.addresses || []).filter(a => a.now && a.address !== ip)", words)
        self.assertIn("' IPv6 address' + (v6 === 1 ? '' : 'es')", words)
        self.assertIn("num(v6)", words)
        self.assertIn('<span class="meta addr">${addressWords(d, !!(d.hint && d.name))}</span>', self.part("viewHome"))

    def test_the_card_shows_every_hardware_address_escaped(self):
        self.assertIn("macsOf(d).map(esc).join(', ')", self.part("addressWords"))
        self.assertIn("Array.isArray(d.macs) && d.macs.length ? d.macs : (d.mac ? [d.mac] : [])", self.part("macsOf"))

    def test_a_device_known_only_by_its_number_says_so_on_its_card(self):
        self.assertIn("${byNumberOnly(d) ? '<span class=\"badge\">Recognised by its number</span>' : ''}",
                      self.part("viewHome"))
        self.assertIn("return d.kind === 'addr' && Number.isInteger(d.id);", self.part("byNumberOnly"))

    def test_the_router_is_called_your_router_until_it_is_named(self):
        self.assertIn("(d.kind === 'hub' ? 'Your router' : 'Unnamed device')", self.part("deviceName"))

    # ----- the device page's addresses

    def test_the_device_page_lists_the_addresses_with_first_and_last_seen(self):
        details = self.part("deviceDetails")
        self.assertIn("(d.addresses || []).map(a =>", details)
        self.assertIn('<span class="title addr">${esc(a.address)}</span>', details)
        self.assertIn("'Last seen here ' + esc(ago(a.last))", details)
        self.assertIn("'first seen here ' + esc(ago(a.first))", details)
        self.assertIn("${deviceDetails(d)}", self.part("viewDevice"))

    def test_the_device_page_lists_each_hardware_address_escaped(self):
        details = self.part("deviceDetails")
        self.assertIn('<span class="title addr">${esc(m)}</span>', details)
        self.assertNotIn("${m}", details)
        self.assertEqual(re.findall(r"\$\{(?:a|d|x|m)(?:\.\w+)*\}", details), [])    # nothing is put in as it came

    def test_the_device_page_says_hardware_address_not_mac_to_people(self):
        shown = re.sub(r"\$\{[^}]*\}", "", self.part("deviceDetails") + self.part("mergeBlocks") + self.part("addressWords")
                       + self.action("separate") + self.page[self.page.index("async function mergeFlow("):
                                                             self.page.index("const actions = {")])
        self.assertNotRegex(shown, r"\bMACs?\b")
        self.assertIn("hardware address", shown)

    # ----- pickers by device name

    def test_pickers_list_devices_by_name_in_name_order(self):
        self.assertIn("${byName(S.devices).map(d => opt(scopeOf(keyOf(d)), pickerLabel(d))).join('')}", self.page)
        self.assertIn("deviceName(a).localeCompare(deviceName(b))", self.part("byName"))

    def test_a_picker_adds_an_address_only_to_tell_two_same_named_devices_apart(self):
        label = self.part("pickerLabel")
        self.assertIn("if(S.devices.filter(x => deviceName(x) === name).length < 2) return name;", label)
        self.assertIn("(d.ip || macsOf(d)[0] || 'not on your network now')", label)

    def test_picker_labels_are_escaped_where_they_are_shown(self):
        self.assertIn('<option value="${esc(keyOf(x))}">${esc(pickerLabel(x))}</option>', self.part("deviceDetails"))
        self.assertIn('<option value="${esc(v)}" ${e.scope === v ? \'selected\' : \'\'}>${esc(label)}</option>',
                      self.part("scheduleForm"))
        self.assertIn("return known ? pickerLabel(known) : 'A device QuietNet no longer lists';", self.part("scopeText"))

    def test_the_group_page_lists_devices_by_name_and_names_them_by_card(self):
        group = self.part("viewGroup")
        self.assertIn("byName(S.devices.filter(d => d.group === g.id))", group)
        self.assertIn('data-act="member" data-device="${esc(keyOf(d))}" data-in="1"', group)
        self.assertIn("api('/api/device-group', Object.assign(byDevice(d.device), {group:d.in ? S.group : null}))", self.page)

    # ----- Merge

    def test_merge_with_offers_the_other_devices_but_never_this_computer_or_the_router(self):
        choices = self.part("mergeChoices")
        self.assertIn("const ok = x => Number.isInteger(x.id) && (x.kind === 'hw' || x.kind === 'addr');", choices)
        self.assertIn("ok(d) ? byName(S.devices.filter(x => ok(x) && x.id !== d.id)) : []", choices)

    def test_merge_asks_for_the_preview_before_anything_else(self):
        flow = self.page[self.page.index("async function mergeFlow("):self.page.index("const actions = {")]
        ask = flow.index("api('/api/merge', {device, 'with':other})")
        shown = flow.index("await askPreview(")
        done = flow.index("api('/api/merge', {device, 'with':other, seen:p.marker})")
        self.assertLess(ask, shown)
        self.assertLess(shown, done)
        self.assertIn("if(!yes) return null;", flow[shown:done])

    def test_merge_is_only_ever_sent_with_the_marker_of_the_preview_shown(self):
        self.assertEqual(self.script.count("seen:p.marker"), 2)          # once for Merge, once for Separate
        self.assertEqual(self.script.count("seen:"), 2)

    def test_an_out_of_date_preview_is_shown_again_not_applied(self):
        flow = self.page[self.page.index("async function mergeFlow("):self.page.index("const actions = {")]
        self.assertIn("for(;;){", flow)
        self.assertIn("catch(e){ if(e.status !== 409) return e; await oops(e); }", flow)
        self.assertIn("err.status = r.status;", self.page)

    def test_the_merge_preview_shows_each_hardware_address_and_marks_what_is_new_or_stops(self):
        blocks = self.part("mergeBlocks")
        self.assertIn("'Hardware address ' + h.mac + ' (now ' + h.label + ')'", blocks)
        self.assertIn("tag:x['new'] ? 'New for it' : ''", blocks)
        self.assertIn("tag:'Stops applying', cls:'warn'", blocks)
        self.assertIn("none: 'Only what is set for the whole house.'", blocks)

    def test_everything_in_a_preview_is_escaped(self):
        box = self.part("askPreview")
        for shown in ("${esc(title)}", "${esc(intro)}", "${esc(b.head)}", "${esc(x.text)}", "${esc(x.tag)}",
                      "${esc(b.none)}", "${esc(t)}", "${esc(b.label)}", "${esc(x.cls || 'accent')}",
                      "${esc(b.cls || '')}", "${esc(i)}"):
            self.assertIn(shown, box)
        raw = [m for m in re.findall(r"\$\{([^`{}]+)\}", box) if not m.startswith("esc(")]
        self.assertEqual(raw, [])

    def test_a_preview_is_never_confirmed_by_the_enter_key(self):
        box = self.part("askPreview")
        self.assertIn("$('mNo').focus();", box)
        self.assertIn("m.onkeydown = e => { if(e.key === 'Escape') done(null); };", box)
        self.assertNotIn("Enter", box)

    def test_merging_from_a_device_page_merges_into_the_open_device_and_stays_on_it(self):
        merge = self.action("merge")
        self.assertIn("const r = await mergeFlow(id, other);", merge)
        self.assertIn("else if(r) S.device = 'd' + r.device;", merge)
        self.assertIn('<button class="btn" data-act="merge" aria-haspopup="dialog">', self.part("deviceDetails"))

    def test_the_page_says_quietnet_never_merges_by_itself(self):
        self.assertIn("QuietNet never merges devices by itself.", self.part("deviceDetails"))

    # ----- the "Same device?" question

    def test_yes_to_same_device_goes_through_the_merge_preview(self):
        answer = self.action("moverules")
        self.assertIn("if(d.todev && d.fromdev){", answer)
        self.assertIn("const r = await mergeFlow(d.fromdev, d.todev);", answer)
        self.assertLess(answer.index("mergeFlow(d.fromdev, d.todev)"), answer.index("api('/api/move-rules', body)"))

    def test_an_older_pi_without_merge_is_asked_the_way_it_always_was(self):
        answer = self.action("moverules")
        self.assertIn("if(r.status !== 404){ await oops(r); return refresh(true); }", answer)
        self.assertIn("api('/api/move-rules', body)", answer)

    def test_the_gone_quiet_notice_asks_same_device(self):
        self.assertIn("It may be the same one with a new private Wi-Fi address. Same device?", self.part("movedNotices"))

    # ----- Separate

    def test_separate_is_offered_only_for_a_device_with_more_than_one_hardware_address(self):
        details = self.part("deviceDetails")
        self.assertIn("const canSeparate = d.kind === 'hw' && Number.isInteger(d.id) && macs.length > 1;", details)
        self.assertIn('${canSeparate ? `<button class="btn" data-act="separate" data-mac="${esc(m)}" '
                      'aria-haspopup="dialog">Separate&hellip;</button>` : \'\'}', details)

    def test_separate_asks_for_the_preview_then_whether_the_rules_go_with_it(self):
        separate = self.action("separate")
        ask = separate.index("api('/api/separate', {device:id, mac:d.mac})")
        shown = separate.index("await askPreview(")
        done = separate.index("api('/api/separate', {device:id, mac:d.mac, rules, seen:p.marker})")
        self.assertLess(ask, shown)
        self.assertLess(shown, done)
        self.assertIn("if(!rules) return;", separate[shown:done])
        self.assertIn("Do the rules go with it?", separate)

    def test_separate_has_no_default_answer_about_the_rules(self):
        separate = self.action("separate")
        self.assertIn("{label:'Separate, with the same rules', value:'copy'}", separate)
        self.assertIn("{label:'Separate, with no rules', value:'none'}", separate)
        self.assertNotIn("cls:'primary'", separate)

    # ----- the three looks

    def test_the_new_parts_use_only_colour_and_size_names_every_look_sets(self):
        new_rules = self.css[self.css.index(".modal .card.wide{"):self.css.index("/* The page frame")]
        used = set(re.findall(r"var\((--[a-z0-9-]+)\)", new_rules))
        self.assertTrue(used)
        looks = [self.css[self.css.index(start):] for start in
                 (':root, [data-theme="calm"]{', '[data-theme="household"]{', '[data-theme="control"]{')]
        for name in used:
            for look in looks:
                self.assertIn(name + ":", look[:look.index("}")], name)

    def test_the_new_parts_carry_no_fixed_colours_or_inline_styles(self):
        new_rules = self.css[self.css.index(".modal .card.wide{"):self.css.index("/* The page frame")]
        self.assertNotRegex(new_rules, r"#[0-9a-fA-F]{3,8}\b")
        for name in ("deviceDetails", "askPreview", "mergeBlocks", "addressWords"):
            self.assertNotIn("style=", self.part(name))

    def test_the_page_still_has_no_emoji(self):
        self.assertNotRegex(self.page, "[\U0001F000-\U0001FAFF☀-➿️]")


if __name__ == "__main__":
    unittest.main()
