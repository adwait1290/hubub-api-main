"""
http://flask.pocoo.org/docs/0.11/patterns/celery/
"""
from celery import Celery


def make_celery(app):
    celery = Celery(
        app.name,
        backend=app.hububconfig['BROKER_URL'],
        broker=app.hububconfig['BROKER_URL'])
    celery.conf.update(app.hububconfig)
    TaskBase = celery.Task
    class ContextTask(TaskBase):
        abstract = True
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return TaskBase.__call__(self, *args, **kwargs)
    celery.Task = ContextTask
    return celery
