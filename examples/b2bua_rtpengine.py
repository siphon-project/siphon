"""
SIPhon B2BUA script with RTPEngine media anchoring.

Used for functional testing: anchors media through a mock RTPEngine
on INVITE (offer) and 200 OK (answer), deletes on BYE.
"""
from siphon import b2bua, rtpengine, log


@b2bua.on_invite
async def on_invite(call):
    log.info(f"B2BUA INVITE: {call.from_uri} -> {call.to_uri}")

    # Anchor media through RTPEngine (offer direction)
    await rtpengine.offer(call, profile="srtp_to_rtp")
    log.info(f"RTPEngine offer done for call {call.call_id}")

    # Dial the B-leg
    call.dial(str(call.ruri))


@b2bua.on_answer
async def on_answer(call, reply):
    log.info(f"B2BUA answer: call {call.call_id}")

    # Anchor media through RTPEngine (answer direction)
    # Pass `call` so RTPEngine uses the A-leg Call-ID that matched the offer.
    await rtpengine.answer(reply, profile="srtp_to_rtp", call=call)
    log.info(f"RTPEngine answer done for call {call.call_id}")


@b2bua.on_bye
async def on_bye(call, initiator):
    log.info(f"B2BUA BYE: call {call.call_id}, initiator={initiator.side}")

    # Release RTPEngine session
    await rtpengine.delete(call)
    log.info(f"RTPEngine delete done for call {call.call_id}")
