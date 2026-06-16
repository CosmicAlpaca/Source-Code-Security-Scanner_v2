from flask import redirect, request

def bad():
    # ruleid: py-open-redirect
    return redirect(request.args.get('next'))

def bad2():
    # ruleid: py-open-redirect
    return redirect(request.args['url'])

def good():
    # ok: py-open-redirect
    return redirect('/dashboard')
