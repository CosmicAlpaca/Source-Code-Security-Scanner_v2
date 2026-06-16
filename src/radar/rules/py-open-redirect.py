from flask import redirect, request

def bad():
    url = request.args.get('next')
    # ruleid: py-open-redirect
    return redirect(url)

def good():
    # ok: py-open-redirect
    return redirect('/dashboard')
