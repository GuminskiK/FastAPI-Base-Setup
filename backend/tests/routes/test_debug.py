from app.main import app


def test_endpoints(client):
    for r in app.routes:
        if hasattr(r, 'methods'):
            print(f'{r.methods} {r.path}')

