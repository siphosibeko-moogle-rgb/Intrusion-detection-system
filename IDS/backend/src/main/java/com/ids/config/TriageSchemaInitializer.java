package com.ids.config;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;

/**
 * Runs db/triage_verdict_schema.sql at startup, same pattern and rationale
 * as ThrottleSchemaInitializer. Belt-and-braces alongside TriageVerdictEntity
 * (which Hibernate's ddl-auto=update also provisions) — whichever runs
 * first creates the table; the other is a no-op.
 */
@Component
public class TriageSchemaInitializer implements InitializingBean {

    private final DataSource dataSource;

    public TriageSchemaInitializer(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public void afterPropertiesSet() {
        new ResourceDatabasePopulator(
                new ClassPathResource("db/triage_verdict_schema.sql"))
            .execute(dataSource);
    }
}
