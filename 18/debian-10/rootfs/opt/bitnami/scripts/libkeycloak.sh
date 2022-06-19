#!/bin/bash
#
# Bitnami Keycloak library

# shellcheck disable=SC1090,SC1091

# Load Generic Libraries
. /opt/bitnami/scripts/libfs.sh
. /opt/bitnami/scripts/liblog.sh
. /opt/bitnami/scripts/libnet.sh
. /opt/bitnami/scripts/libos.sh
. /opt/bitnami/scripts/libfile.sh
. /opt/bitnami/scripts/libvalidations.sh

########################
# Validate settings in KEYCLOAK_* env. variables
# Globals:
#   KEYCLOAK_*
# Arguments:
#   None
# Returns:
#   None
#########################
keycloak_validate() {
    info "Validating settings in KEYCLOAK_* env vars..."
    local error_code=0

    # Auxiliary functions
    print_validation_error() {
        error "$1"
        error_code=1
    }

    check_allowed_port() {
        local port_var="${1:?missing port variable}"
        local -a validate_port_args=()
        ! am_i_root && validate_port_args+=("-unprivileged")
        validate_port_args+=("${!port_var}")
        if ! err=$(validate_port "${validate_port_args[@]}"); then
            print_validation_error "An invalid port was specified in the environment variable ${port_var}: ${err}."
        fi
    }

    if is_boolean_yes "$KEYCLOAK_PRODUCTION"; then
        if [[ "$KEYCLOAK_PROXY" == "edge" ]]; then
            # https://www.keycloak.org/server/reverseproxy
            if is_boolean_yes "$KEYCLOAK_ENABLE_TLS"; then
                print_validation_error "TLS and proxy=edge are not compatible. Please set the KEYCLOAK_ENABLE_TLS variable to false when using KEYCLOAK_PROXY=edge. Review # https://www.keycloak.org/server/reverseproxy for more information about proxy settings."
            fi
        elif ! is_boolean_yes "$KEYCLOAK_ENABLE_TLS"; then
            # keycloak proxy passthrough/reencrypt requires tls
            print_validation_error "You need to have TLS enabled. Please set the KEYCLOAK_ENABLE_TLS variable to true"
        fi
    fi

    if is_boolean_yes "$KEYCLOAK_ENABLE_TLS"; then
        if is_empty_value "$KEYCLOAK_TLS_TRUSTSTORE_FILE"; then
            print_validation_error "Path to the TLS truststore file not defined. Please set the KEYCLOAK_TLS_TRUSTSTORE_FILE variable to the mounted truststore"
        fi
        if is_empty_value "$KEYCLOAK_TLS_KEYSTORE_FILE"; then
            print_validation_error "Path to the TLS keystore file not defined. Please set the KEYCLOAK_TLS_KEYSTORE_FILE variable to the mounted keystore"
        fi
    fi

    if ! validate_ipv4 "${KEYCLOAK_BIND_ADDRESS}"; then
        if ! is_hostname_resolved "${KEYCLOAK_BIND_ADDRESS}"; then
            print_validation_error print_validation_error "The value for KEYCLOAK_BIND_ADDRESS ($KEYCLOAK_BIND_ADDRESS) should be an IPv4 address or it must be a resolvable hostname"
        fi
    fi

    if [[ "$KEYCLOAK_HTTP_PORT" -eq "$KEYCLOAK_HTTPS_PORT" ]]; then
        print_validation_error "KEYCLOAK_HTTP_PORT and KEYCLOAK_HTTPS_PORT are bound to the same port!"
    fi
    check_allowed_port KEYCLOAK_HTTP_PORT
    check_allowed_port KEYCLOAK_HTTPS_PORT

    for var in KEYCLOAK_CREATE_ADMIN_USER KEYCLOAK_ENABLE_TLS KEYCLOAK_ENABLE_STATISTICS; do
        if ! is_true_false_value "${!var}"; then
            print_validation_error "The allowed values for $var are [true, false]"
        fi
    done

    # Deprecation warnings
    is_empty_value "${KEYCLOAK_FRONTEND_URL:-}" || warn "The usage of 'KEYCLOAK_FRONTEND_URL' is deprecated and will soon be removed. Use 'KC_HOSTNAME' instead."

    [[ "$error_code" -eq 0 ]] || exit "$error_code"
}

########################
# Add or modify an entry in the Discourse configuration file
# Globals:
#   KEYCLOAK_*
# Arguments:
#   $1 - Variable name
#   $2 - Value to assign to the variable
# Returns:
#   None
#########################
keycloak_conf_set() {
    local -r key="${1:?key missing}"
    local -r value="${2:-}"
    debug "Setting ${key} to '${value}' in Keycloak configuration"
    # Sanitize key (sed does not support fixed string substitutions)
    local sanitized_pattern
    sanitized_pattern="^\s*(#\s*)?$(sed 's/[]\[^$.*/]/\\&/g' <<<"$key")\s*=\s*(.*)"
    local entry="${key} = ${value}"
    # Check if the configuration exists in the file
    if grep -q -E "$sanitized_pattern" "${KEYCLOAK_CONF_DIR}/${KEYCLOAK_CONF_FILE}"; then
        # It exists, so replace the line
        replace_in_file "${KEYCLOAK_CONF_DIR}/${KEYCLOAK_CONF_FILE}" "$sanitized_pattern" "$entry"
    else
        echo "$entry" >>"${KEYCLOAK_CONF_DIR}/${KEYCLOAK_CONF_FILE}"
    fi
}

########################
# Configure database settings
# Globals:
#   KEYCLOAK_*
# Arguments:
#   None
# Returns:
#   None
#########################
keycloak_configure_database() {
    # Prepare JDBC Params if set - add '?' at the beginning if the value is not empty and doesn't start with '?'
    local jdbc_params
    jdbc_params="$(echo "$KEYCLOAK_JDBC_PARAMS" | sed -E '/^$|^\?+.*$/!s/^/?/')"

    info "Configuring database settings"
    debug_execute jboss-cli.sh <<EOF
embed-server --server-config=${KEYCLOAK_CONF_FILE} --std-out=echo
batch
/subsystem=datasources/data-source=KeycloakDS: remove()
/subsystem=datasources/data-source=KeycloakDS: add(jndi-name=java:jboss/datasources/KeycloakDS,enabled=true,use-java-context=true,use-ccm=true, connection-url="jdbc:oracle:thin:@//${KEYCLOAK_DATABASE_HOST}:${KEYCLOAK_DATABASE_PORT}/${KEYCLOAK_DATABASE_NAME}${jdbc_params}", driver-name=oracle)
/subsystem=datasources/data-source=KeycloakDS: write-attribute(name=user-name, value=\${env.KEYCLOAK_DATABASE_USER})
/subsystem=datasources/data-source=KeycloakDS: write-attribute(name=check-valid-connection-sql, value="SELECT 1 FROM DUAL")
/subsystem=datasources/data-source=KeycloakDS: write-attribute(name=background-validation, value=true)
/subsystem=datasources/data-source=KeycloakDS: write-attribute(name=background-validation-millis, value=60000)
/subsystem=datasources/data-source=KeycloakDS: write-attribute(name=flush-strategy, value=IdleConnections)
/subsystem=datasources/jdbc-driver=oracle:add(driver-name=oracle, driver-module-name=com.oracle, driver-xa-datasource-class-name=oracle.jdbc.xa.client.OracleXADataSource)
/subsystem=keycloak-server/spi=connectionsJpa/provider=default:write-attribute(name=properties.schema,value=${KEYCLOAK_DATABASE_SCHEMA})
run-batch
stop-embedded-server
EOF

    if ! is_empty_value "$KEYCLOAK_DATABASE_PASSWORD"; then
        debug_execute jboss-cli.sh <<EOF
embed-server --server-config=${KEYCLOAK_CONF_FILE} --std-out=echo
batch
/subsystem=datasources/data-source=KeycloakDS: write-attribute(name=password, value=\${env.KEYCLOAK_DATABASE_PASSWORD})
run-batch
stop-embedded-server
EOF
    fi
}

########################
# Configure JGroups settings using JBoss CLI
# Globals:
#   KEYCLOAK_*
# Arguments:
#   None
# Returns:
#   None
#########################
keycloak_configure_jgroups() {
    info "Configuring jgroups settings"
    if [[ "$KEYCLOAK_JGROUPS_DISCOVERY_PROTOCOL" == "JDBC_PING" ]]; then
        debug_execute jboss-cli.sh <<EOF
embed-server --server-config=${KEYCLOAK_CONF_FILE} --std-out=echo
batch
/subsystem=jgroups/stack=udp/protocol=PING:remove()
/subsystem=jgroups/stack=udp/protocol=JDBC_PING:add(add-index=0, data-source=KeycloakDS, properties={${KEYCLOAK_JGROUPS_DISCOVERY_PROPERTIES}})
/subsystem=jgroups/stack=tcp/protocol=MPING:remove()
/subsystem=jgroups/stack=tcp/protocol=JDBC_PING:add(add-index=0, data-source=KeycloakDS, properties={${KEYCLOAK_JGROUPS_DISCOVERY_PROPERTIES}})
/subsystem=jgroups/channel=ee:write-attribute(name="stack", value=${KEYCLOAK_JGROUPS_TRANSPORT_STACK})
run-batch
stop-embedded-server
EOF
    else
        debug_execute jboss-cli.sh <<EOF
embed-server --server-config=${KEYCLOAK_CONF_FILE} --std-out=echo
batch
/subsystem=jgroups/stack=udp/protocol=PING:remove()
/subsystem=jgroups/stack=udp/protocol=${KEYCLOAK_JGROUPS_DISCOVERY_PROTOCOL}:add(add-index=0, properties={${KEYCLOAK_JGROUPS_DISCOVERY_PROPERTIES}})
/subsystem=jgroups/stack=tcp/protocol=MPING:remove()
/subsystem=jgroups/stack=tcp/protocol=${KEYCLOAK_JGROUPS_DISCOVERY_PROTOCOL}:add(add-index=0, properties={${KEYCLOAK_JGROUPS_DISCOVERY_PROPERTIES}})
/subsystem=jgroups/channel=ee:write-attribute(name="stack", value=${KEYCLOAK_JGROUPS_TRANSPORT_STACK})
run-batch
stop-embedded-server
EOF
    fi
}

########################
# Configure cluster caching
# Globals:
#   KEYCLOAK_*
# Arguments:
#   None
# Returns:
#   None
#########################
keycloak_configure_cache() {
    info "Configuring cache count"
    keycloak_conf_set "cache" "$KEYCLOAK_CACHE_TYPE"
    if ! is_empty_value "$KEYCLOAK_CACHE_STACK"; then
        debug_execute kc.sh build --cache-stack="${KEYCLOAK_CACHE_STACK}"
    fi
}

########################
# Enable statistics
# Globals:
#   KEYCLOAK_*
# Arguments:
#   None
# Returns:
#   None
#########################
keycloak_configure_metrics() {
    info "Enabling statistics"
    keycloak_conf_set "metrics-enabled" "$KEYCLOAK_ENABLE_STATISTICS"
}

########################
# Configure hostname
# Globals:
#   KEYCLOAK_*
# Arguments:
#   None
# Returns:
#   None
#########################
keycloak_configure_hostname() {
    info "Configuring hostname settings"
    keycloak_conf_set "hostname-strict" "false"
}

########################
# Configure http
# Globals:
#   KEYCLOAK_*
# Arguments:
#   None
# Returns:
#   None
#########################
keycloak_configure_http() {
    info "Configuring http settings"
    keycloak_conf_set "http-enabled" "true"
    keycloak_conf_set "https-stric" "false"
    keycloak_conf_set "http-port" "${KEYCLOAK_HTTP_PORT}"
    keycloak_conf_set "https-port" "${KEYCLOAK_HTTPS_PORT}"
}

########################
# Configure logging settings
# Globals:
#   KEYCLOAK_*
# Arguments:
#   None
# Returns:
#   None
#########################
keycloak_configure_loglevel() {
    info "Configuring log level"
    keycloak_conf_set "log-level" "${KEYCLOAK_LOG_LEVEL}"
    keycloak_conf_set "log-console-output" "${KEYCLOAK_LOG_OUTPUT}"
}

########################
# Configure proxy settings using JBoss CLI
# Globals:
#   KEYCLOAK_*
# Arguments:
#   None
# Returns:
#   None
#########################
keycloak_configure_proxy() {
    info "Configuring proxy"
    keycloak_conf_set "proxy" "${KEYCLOAK_PROXY}"
}

########################
# Configure node identifier
# Globals:
#   KEYCLOAK_*
# Arguments:
#   None
# Returns:
#   None
#########################
keycloak_configure_node_identifier() {
    info "Configuring node identifier"
    debug_execute jboss-cli.sh <<EOF
embed-server --server-config=${KEYCLOAK_CONF_FILE} --std-out=echo
batch
/subsystem=transactions:write-attribute(name=node-identifier, value=\${jboss.node.name})
run-batch
stop-embedded-server
EOF
}

########################
# Initialize keycloak installation
# Globals:
#   KEYCLOAK_*
# Arguments:
#   None
# Returns:
#   None
#########################
keycloak_initialize() {
    # Clean to avoid issues when running docker restart
    keycloak_clean_from_restart

    # Wait for database
    info "Trying to connect to Oracle server $KEYCLOAK_DATABASE_HOST..."
    if ! retry_while "wait-for-port --host $KEYCLOAK_DATABASE_HOST --timeout 10 $KEYCLOAK_DATABASE_PORT" "$KEYCLOAK_INIT_MAX_RETRIES"; then
        error "Unable to connect to host $KEYCLOAK_DATABASE_HOST"
        exit 1
    else
        info "Found Oracle server listening at $KEYCLOAK_DATABASE_HOST:$KEYCLOAK_DATABASE_PORT"
    fi

    if ! is_dir_empty "$KEYCLOAK_MOUNTED_CONF_DIR"; then
        cp -Lr "$KEYCLOAK_MOUNTED_CONF_DIR"/* "$KEYCLOAK_CONF_DIR"
    fi
    keycloak_configure_database
    keycloak_configure_metrics
    keycloak_configure_http
    keycloak_configure_hostname
    keycloak_configure_cache
    keycloak_configure_loglevel
    keycloak_configure_proxy
    is_boolean_yes "$KEYCLOAK_ENABLE_TLS" && keycloak_configure_tls
    true
}

########################
# Run custom initialization scripts
# Globals:
#   KEYCLOAK_*
# Arguments:
#   None
# Returns:
#   None
#########################
keycloak_custom_init_scripts() {
    if [[ -n $(find "${KEYCLOAK_INITSCRIPTS_DIR}/" -type f -regex ".*\.sh") ]] && [[ ! -f "${KEYCLOAK_INITSCRIPTS_DIR}/.user_scripts_initialized" ]]; then
        info "Loading user's custom files from ${KEYCLOAK_INITSCRIPTS_DIR} ..."
        local -r tmp_file="/tmp/filelist"
        find "${KEYCLOAK_INITSCRIPTS_DIR}/" -type f -regex ".*\.sh" | sort >"$tmp_file"
        while read -r f; do
            case "$f" in
            *.sh)
                if [[ -x "$f" ]]; then
                    debug "Executing $f"
                    "$f"
                else
                    debug "Sourcing $f"
                    . "$f"
                fi
                ;;
            *) debug "Ignoring $f" ;;
            esac
        done <$tmp_file
        rm -f "$tmp_file"
        touch "$KEYCLOAK_VOLUME_DIR"/.user_scripts_initialized
    fi
}
