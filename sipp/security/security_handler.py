from siphon import proxy


@proxy.on_request
def on_request(request):
    # Echo a 200 OK for anything that reaches the script. A request dropped by
    # the security filter (scanner User-Agent or rate-limit ban) never gets
    # here — the client sees silence, which is exactly how the test
    # distinguishes "blocked" from "allowed".
    request.reply(200, "OK")
