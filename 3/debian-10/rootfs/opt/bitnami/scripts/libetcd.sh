#!/bin/bash
#
# Bitnami etcd library

# shellcheck disable=SC1090
# shellcheck disable=SC1091

# Load Generic Libraries
. /opt/bitnami/scripts/libfile.sh
. /opt/bitnami/scripts/libfs.sh
. /opt/bitnami/scripts/liblog.sh
. /opt/bitnami/scripts/libos.sh
. /opt/bitnami/scripts/libnet.sh
. /opt/bitnami/scripts/libservice.sh

# Functions

########################
# Validate settings in ETCD_* environment variables
# Globals:
#   ETCD_*
# Arguments:
#   None
# Returns:
#   None
#########################
etcd_validate() {
    info "Validating settings in ETCD_* env vars.."
    local error_code=0

    # Auxiliary functions
    print_validation_error() {
        error "$1"
        error_code=1
    }

    if is_boolean_yes "$ALLOW_NONE_AUTHENTICATION"; then
        warn "You set the environment variable ALLOW_NONE_AUTHENTICATION=${ALLOW_NONE_AUTHENTICATION}. For safety reasons, do not use this flag in a production environment."
    else
        is_empty_value "$ETCD_ROOT_PASSWORD" && print_validation_error "The ETCD_ROOT_PASSWORD environment variable is empty or not set. Set the environment variable ALLOW_NONE_AUTHENTICATION=yes to allow a blank password. This is only recommended for development environments."
    fi

    [[ "$error_code" -eq 0 ]] || return "$error_code"
}

########################
# Check if etcd is running
# Arguments:
#   None
# Returns:
#   Boolean
#########################
is_etcd_running() {
    local -r pid="$(pgrep -f "^etcd")"

    if [[ -n "$pid" ]]; then
        is_service_running "$pid"
    else
        false
    fi
}

########################
# Stop etcd
# Arguments:
#   None
# Returns:
#   None
#########################
etcd_stop() {
    local pid
    ! is_etcd_running && return
    
    info "Stopping etcd"
    pid="$(pgrep -f "^etcd")"
    local counter=10
    kill "$pid"
    while [[ "$counter" -ne 0 ]] && is_service_running "$pid"; do
        sleep 1
        counter=$((counter - 1))
    done
}

########################
# Start etcd in background
# Arguments:
#   None
# Returns:
#   None
#########################
etcd_start_bg() {
    is_etcd_running && return
    
    info "Starting etcd in background"
    debug_execute "etcd" &
    sleep 3
}

########################
# Obtain endpoints to connect when running 'ectdctl'
# Globals:
#   ETCD_*
# Arguments:
#   $1 - exclude current member from the list (default: false)
# Returns:
#   String
########################
etcdctl_get_endpoints() {
    local only_others=${1:-false}
    local host port endpoints

    endpoints="${ETCDCTL_ENDPOINTS:-}"
    if retry_while "etcdctl member list" >/dev/null 2>&1; then
        endpoints="$(etcdctl member list | awk -F "," '{print $5}' | awk -F "//" '{print $2}' | tr -d ' ' | tr '\n' ',' | sed 's/,*$//g')"
        if [[ $only_others = true ]]; then
            host="$(parse_uri "$ETCD_ADVERTISE_CLIENT_URLS" "host")"
            port="$(parse_uri "$ETCD_ADVERTISE_CLIENT_URLS" "port")"
            endpoints="$(tr -s , <<< "${endpoints//${host}:${port}/}")"
        fi
    fi
    echo "$endpoints"
}

########################
# Obtain etcdctl authentication flags to use
# Globals:
#   ETCD_*
# Arguments:
#   None
# Returns:
#   Array with extra flags to use for authentication
#########################
etcdctl_auth_flags() {
    local -a authFlags=()

    ! is_empty_value "$ETCD_ROOT_PASSWORD" && authFlags+=("--user" "root:$ETCD_ROOT_PASSWORD")
    if [[ $ETCD_PEER_AUTO_TLS = true ]]; then
        authFlags+=("--cert" "${ETCD_DATA_DIR}/fixtures/client/cert.pem" "--key" "${ETCD_DATA_DIR}/fixtures/client/key.pem")
    else
        [[ -f "$ETCD_CERT_FILE" ]] && [[ -f "$ETCD_KEY_FILE" ]] && authFlags+=("--cert" "$ETCD_CERT_FILE" "--key" "$ETCD_KEY_FILE")
        [[ -f "$ETCD_TRUSTED_CA_FILE" ]] && authFlags+=("--cacert" "$ETCD_TRUSTED_CA_FILE")
    fi
    echo "${authFlags[@]}"
}

########################
# Stores etcd member ID in the data directory
# Globals:
#   ETCD_*
# Arguments:
#   None
# Returns:
#   None
########################
etcd_store_member_id() {
    local -a extra_flags

    read -r -a extra_flags <<< "$(etcdctl_auth_flags)"
    extra_flags+=("--endpoints=$(etcdctl_get_endpoints)")
    (unset -v ETCDCTL_ENDPOINTS; etcdctl member list "${extra_flags[@]}" | grep -w "$ETCD_ADVERTISE_CLIENT_URLS" | awk -F "," '{ print $1}' > "${ETCD_DATA_DIR}/member_id")
    debug "Stored member ID: $(cat "${ETCD_DATA_DIR}/member_id")"
}

########################
# Configure etcd RBAC (do not confuse with K8s RBAC)
# Globals:
#   ETCD_*
# Arguments:
#   None
# Returns:
#   None
########################
etcd_configure_rbac() {
    info "Enabling etcd authentication"

    ! is_etcd_running && etcd_start_bg
    debug_execute etcdctl user add root --interactive=false <<< "$ETCD_ROOT_PASSWORD"
    debug_execute etcdctl user grant-role root root
    debug_execute etcdctl auth enable
    etcd_stop
}

########################
# Checks if the member was successfully removed from the cluster
# Globals:
#   ETCD_*
# Arguments:
#   None
# Returns:
#   None
########################
was_etcd_member_removed() {
    local return_value=0

    if grep -sqE "^Member[[:space:]]+[a-z0-9]+\s+removed\s+from\s+cluster\s+[a-z0-9]+$" "${ETCD_VOLUME_DIR}/member_removal.log"; then
        debug "Removal was properly recorded in member_removal.log"
        rm -rf "${ETCD_DATA_DIR:?}/"*
    elif [[ ! -d "${ETCD_DATA_DIR}/member/snap" ]] && [[ ! -f "$ETCD_DATA_DIR/member_id" ]]; then
        debug "Missing member data"
        rm -rf "${ETCD_DATA_DIR:?}/"*
    else
        return_value=1
    fi
    rm -f "${ETCD_VOLUME_DIR}/member_removal.log"
    return $return_value
}

########################
# Checks if there are enough active members
# Globals:
#   ETCD_*
# Arguments:
#   None
# Returns:
#   None
########################
is_healthy_cluster() {
    local return_value=0
    local active_endpoints=0
    local -a extra_flags

    read -r -a endpoints_array <<< "$(tr ',;' ' ' <<< "$(etcdctl_get_endpoints)")"
    local -r cluster_size=${#endpoints_array[@]}
    for e in "${endpoints_array[@]}"; do
        read -r -a extra_flags <<< "$(etcdctl_auth_flags)"
        extra_flags+=("--endpoints=$e")
        if [[ "$e" != "$ETCD_ADVERTISE_CLIENT_URLS" ]] && (unset -v ETCDCTL_ENDPOINTS; etcdctl endpoint health "${extra_flags[@]}" >/dev/null 2>&1); then
            debug "$e endpoint is active"
            active_endpoints+=1
        fi
    done

    if is_boolean_yes "$ETCD_DISASTER_RECOVERY"; then
        if [[ -f "/snapshots/.disaster_recovery" ]]; then
            if [[ $active_endpoints -eq $((cluster_size - 1)) ]]; then
                debug "Last member to recover from the disaster!"
                rm "/snapshots/.disaster_recovery"
            fi
            return_value=1
        else
            if [[ $active_endpoints -lt $(((cluster_size + 1)/2)) ]]; then
                debug "There are no enough active endpoints!"
                touch "/snapshots/.disaster_recovery"
                return_value=1
            fi
        fi
    else
        if [[ $active_endpoints -lt $(((cluster_size + 1)/2)) ]]; then
            debug "There are no enough active endpoints!"
            return_value=1
        fi
    fi

    return $return_value
}

########################
# Ensure etcd is initialized
# Globals:
#   ETCD_*
# Arguments:
#   None
# Returns:
#   None
#########################
etcd_initialize() {
    local -a extra_flags initial_members

    info "Initializing etcd"
    read -r -a initial_members <<< "$(tr ',;' ' ' <<< "$ETCD_INITIAL_CLUSTER")"
    if is_mounted_dir_empty "$ETCD_DATA_DIR"; then
        info "There is no data from previous deployments"
        if [[ ${#initial_members[@]} -gt 1 ]]; then
            if [[ "$ETCD_INITIAL_CLUSTER_STATE" = "new" ]] && [[ $ETCD_INITIAL_CLUSTER = *"$ETCD_INITIAL_ADVERTISE_PEER_URLS"* ]]; then
                info "Bootstrapping a new cluster"
            else
                info "Adding new member to existing cluster"
                ensure_dir_exists "$ETCD_DATA_DIR"
                read -r -a extra_flags <<< "$(etcdctl_auth_flags)"
                extra_flags+=("--endpoints=$(etcdctl_get_endpoints)" "--peer-urls=$ETCD_INITIAL_ADVERTISE_PEER_URLS")
                (unset -v ETCDCTL_ENDPOINTS; etcdctl member add "$ETCD_NAME" "${extra_flags[@]}" | grep "^ETCD_" > "${ETCD_DATA_DIR}/new_member_envs")
                replace_in_file "${ETCD_DATA_DIR}/new_member_envs" "^" "export "
            fi
        fi
        if is_boolean_yes "$ETCD_START_FROM_SNAPSHOT"; then
            if [[ -f "/init-snapshot/FOO" ]]; then
                info "Restoring snapshot before initializing etcd cluster"
                local -a restore_args=("--data-dir" "$ETCD_DATA_DIR")
                [[ ${#initial_members[@]} -gt 1 ]] && restore_args+=(
                    "--name" "$ETCD_NAME"
                    "--initial-cluster" "$ETCD_INITIAL_CLUSTER"
                    "--initial-cluster-token" "$ETCD_INITIAL_CLUSTER_TOKEN"
                    "--initial-advertise-peer-urls" "$ETCD_INITIAL_ADVERTISE_PEER_URLS"
                )
                debug_execute etcdctl snapshot restore "/init-snapshot/FOO" "${restore_args[@]}"
                debug_execute etcd_store_member_id &
            else
                error "There was no snapshot to restore!"
                exit 1
            fi
        else
            if [[ ${#initial_members[@]} -gt 1 ]]; then
                # When there's more than one etcd replica, RBAC should be only enabled in one member
                if ! is_empty_value "$ETCD_ROOT_PASSWORD" && [[ "$ETCD_INITIAL_CLUSTER_STATE" = "new" ]] && [[ "${initial_members[0]}" = *"$ETCD_INITIAL_ADVERTISE_PEER_URLS"* ]]; then
                    etcd_configure_rbac
                else
                    debug "Skipping RBAC configuration in member $ETCD_NAME"
                fi
            else
                ! is_empty_value "$ETCD_ROOT_PASSWORD" && etcd_configure_rbac
            fi
            debug_execute etcd_store_member_id &
        fi
    else
        info "Detected data from previous deployments"
        if [[ $(stat -c "%a" "$ETCD_DATA_DIR") != *700 ]]; then
            debug "Setting data directory permissions to 700 in a recursive way (required in etcd >=3.4.10)"
            chmod -R 700 "$ETCD_DATA_DIR"
        fi
        if [[ ${#initial_members[@]} -gt 1 ]]; then
            if ! is_healthy_cluster; then
                warn "Cluster not responding!"
                if is_boolean_yes "$ETCD_DISASTER_RECOVERY"; then
                    latest_snapshot_file="$(find /snapshots/ -maxdepth 1 -type f -name 'db-*' | sort | tail -n 1)"
                    if [[ "${latest_snapshot_file}" != "" ]]; then
                        info "Restoring etcd cluster from snapshot"
                        rm -rf "$ETCD_DATA_DIR"
                        debug_execute etcdctl snapshot restore "${latest_snapshot_file}" \
                          --name "$ETCD_NAME" \
                          --data-dir "$ETCD_DATA_DIR" \
                          --initial-cluster "$ETCD_INITIAL_CLUSTER" \
                          --initial-cluster-token "$ETCD_INITIAL_CLUSTER_TOKEN" \
                          --initial-advertise-peer-urls "$ETCD_INITIAL_ADVERTISE_PEER_URLS"
                        debug_execute etcd_store_member_id &
                    else
                        error "There was no snapshot to restore!"
                        exit 1
                    fi
                else
                    warn "Disaster recovery is disabled, the cluster will try to recover on it's own"
                fi
            elif was_etcd_member_removed; then
                info "Adding new member to existing cluster"
                read -r -a extra_flags <<< "$(etcdctl_auth_flags)"
                extra_flags+=("--endpoints=$(etcdctl_get_endpoints)" "--peer-urls=$ETCD_INITIAL_ADVERTISE_PEER_URLS")
                (unset -v ETCDCTL_ENDPOINTS; etcdctl member add "$ETCD_NAME" "${extra_flags[@]}" | grep "^ETCD_" > "${ETCD_DATA_DIR}/new_member_envs")
                replace_in_file "${ETCD_DATA_DIR}/new_member_envs" "^" "export "
                debug_execute etcd_store_member_id &
            else
                info "Updating member in existing cluster"
                export ETCD_INITIAL_CLUSTER_STATE=existing
                read -r -a extra_flags <<< "$(etcdctl_auth_flags)"
                extra_flags+=("--endpoints=$(etcdctl_get_endpoints true)" "--peer-urls=$ETCD_INITIAL_ADVERTISE_PEER_URLS")
                (unset -v ETCDCTL_ENDPOINTS; etcdctl member update "$(cat "${ETCD_DATA_DIR}/member_id")" "${extra_flags[@]}")
            fi
        fi
    fi

    # Avoid exit code of previous commands to affect the result of this function
    true
}
