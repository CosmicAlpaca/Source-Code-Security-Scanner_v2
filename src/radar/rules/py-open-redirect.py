from flask import redirect, request

# ruleid: py-open-redirect
def bad():
    return redirect(request.args.get('next'))

# ok: py-open-redirect
def good():
    return redirect('/dashboard')
