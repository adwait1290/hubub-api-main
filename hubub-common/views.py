# -*- coding: utf-8 -*-

__all__ = (
    'BaseView',
)


class BaseView:

    @property
    def default_route(self):
        return '/api/v1'