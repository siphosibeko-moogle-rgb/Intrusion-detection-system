package com.ids.config;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;

/**
 * Runs db/alert_throttle_schema.sql at startup. The project manages its
 * schema with hibernate ddl-auto=update, which cannot express the throttle
 * table (composite INET primary key, no entity), so this applies the plain
 * SQL file instead. Every statement in the file is idempotent, so this is
 * safe on every boot regardless of whether Hibernate has already run.
 *
 * InitializingBean (not ApplicationRunner) so the table exists during
 * context refresh, before the web server starts accepting ingest traffic.
 */
@Component
public class ThrottleSchemaInitializer implements InitializingBean {

    private final DataSource dataSource;

    public ThrottleSchemaInitializer(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public void afterPropertiesSet() {
        new ResourceDatabasePopulator(
                new ClassPathResource("db/alert_throttle_schema.sql"))
            .execute(dataSource);
    }
}
