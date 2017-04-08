#!/usr/bin/env python3

class qos(object):
    __qos_queue = None
    __qsize = 0

    def __init__(self, qsize=20):
        self.__qos_queue = {}

    def add_queue(self, mbuf):
        pass