package com.newland.resilience4j.exception;

import java.util.function.Predicate;

public class RecordFailurePredicate implements Predicate<Throwable> {
    @Override
    public boolean test(Throwable throwable) {
        System.out.println("===========" + System.currentTimeMillis());
        return !(throwable instanceof BusinessException);
    }
}