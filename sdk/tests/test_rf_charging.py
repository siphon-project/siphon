"""Tests for the Rf (3GPP TS 32.299 IMS offline charging) mock surface."""

from siphon_sdk import mock_module


class TestRfMock:
    def setup_method(self):
        mock_module.install()
        mock_module.reset()
        self.diameter = mock_module.get_diameter()
        self.diameter.add_peer("cdf1", connected=True)

    def test_acr_start_returns_session_id(self):
        from siphon import diameter
        result = diameter.rf_acr_start(
            calling_party="sip:alice@ims.example.com",
            called_party="sip:bob@ims.example.com",
            sip_method="INVITE",
            role_of_node="originating",
            node_functionality="scscf",
            ims_charging_identifier="icid-1",
        )
        assert result is not None
        assert result["result_code"] == 2001
        assert result["session_id"]
        assert result["record_number"] == 0

    def test_acr_interim_passes_session_id(self):
        from siphon import diameter
        start = diameter.rf_acr_start(sip_method="INVITE")
        assert start is not None
        sid = start["session_id"]

        interim = diameter.rf_acr_interim(sid, 1, sip_method="INVITE")
        assert interim is not None
        assert interim["session_id"] == sid
        assert interim["record_number"] == 1

    def test_acr_stop_with_termination_cause(self):
        from siphon import diameter
        start = diameter.rf_acr_start(sip_method="INVITE")
        sid = start["session_id"]
        stop = diameter.rf_acr_stop(sid, 2, termination_cause=8,
                                     sip_method="BYE", cause_code=-200)
        assert stop is not None
        assert stop["session_id"] == sid

        captured = self.diameter.captured_acrs()
        assert any(
            entry["record_type"] == "STOP"
            and entry["termination_cause"] == 8
            and entry["cause_code"] == -200
            for entry in captured
        )

    def test_acr_event_one_shot(self):
        from siphon import diameter
        result = diameter.rf_acr_event(
            calling_party="sip:alice@ims.example.com",
            sip_method="REGISTER",
            role_of_node="originating",
            node_functionality="pcscf",
            cause_code=0,
        )
        assert result is not None
        captured = self.diameter.captured_acrs()
        assert len(captured) == 1
        assert captured[0]["record_type"] == "EVENT"
        assert captured[0]["sip_method"] == "REGISTER"

    def test_set_rf_result_code_propagates(self):
        from siphon import diameter
        self.diameter.set_rf_result_code(4002)  # DIAMETER_OUT_OF_SPACE
        result = diameter.rf_acr_start(sip_method="INVITE")
        assert result["result_code"] == 4002

    def test_set_rf_interim_interval_propagates(self):
        from siphon import diameter
        self.diameter.set_rf_interim_interval(600)
        result = diameter.rf_acr_start(sip_method="INVITE")
        assert result["interim_interval"] == 600

    def test_clear_captured_acrs(self):
        from siphon import diameter
        diameter.rf_acr_event(sip_method="REGISTER")
        assert len(self.diameter.captured_acrs()) == 1
        self.diameter.clear_captured_acrs()
        assert self.diameter.captured_acrs() == []

    def test_session_ids_are_unique_per_start(self):
        from siphon import diameter
        first = diameter.rf_acr_start(sip_method="INVITE")
        second = diameter.rf_acr_start(sip_method="INVITE")
        assert first["session_id"] != second["session_id"]
