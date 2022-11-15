package cn.com.glsx.auth.listener;

import org.springframework.context.ApplicationContext;
import org.springframework.context.event.ApplicationContextEvent;

public class SqlSessionEvent extends ApplicationContextEvent {

    /**
     * Create a new ContextStartedEvent.
     *
     * @param source the {@code ApplicationContext} that the event is raised for
     *               (must not be {@code null})
     */
    public SqlSessionEvent(ApplicationContext source) {
        super(source);
    }

}

