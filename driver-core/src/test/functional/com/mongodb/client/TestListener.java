package com.mongodb.client;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

public class TestListener {
    List<String> events = Collections.synchronizedList(new ArrayList<>());

    public void add(final String s) {
        events.add(s);
    }

    public List<String> getEventStrings() {
        return new ArrayList<>(events);
    }

    public void clear() {
        events.clear();
    }
}