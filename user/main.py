import config as conf
import web

if __name__ == '__main__':
    app = web.create_app()
    app.run(port=conf.PORT, debug=True)
