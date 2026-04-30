import streamlit as st
import pandas as pd
from fmc_get_config import FMCAuthenticator, FMCPolicyExtractor
from cpapi import APIClient, APIClientArgs

def fmc_app():
    st.title("Firepower Management Center (FMC) Integrator")

    if "fmc_auth" not in st.session_state:
        st.session_state.fmc_auth = None
    if "fmc_domains" not in st.session_state:
        st.session_state.fmc_domains = []
    if "fmc_selected_domain" not in st.session_state:
        st.session_state.fmc_selected_domain = None
    if "fmc_policies" not in st.session_state:
        st.session_state.fmc_policies = []

    # Login Section
    if st.session_state.fmc_auth is None:
        st.subheader("Login to FMC")
        with st.form("fmc_login_form"):
            host = st.text_input("FMC IP or Hostname")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submit = st.form_submit_button("Login")

            if submit:
                if host and username and password:
                    with st.spinner("Authenticating to FMC..."):
                        auth = FMCAuthenticator(host, username, password)
                        if auth.authenticate():
                            st.session_state.fmc_auth = auth
                            st.success("Successfully authenticated!")
                            st.rerun()
                        else:
                            st.error("Authentication failed. Please check your credentials.")
                else:
                    st.warning("Please fill in all fields.")
    else:
        st.success(f"Connected to FMC at {st.session_state.fmc_auth.fmc_host}")
        if st.button("Logout", key="fmc_logout"):
            st.session_state.fmc_auth = None
            st.session_state.fmc_selected_domain = None
            st.session_state.fmc_domains = []
            st.session_state.fmc_policies = []
            st.rerun()

        st.divider()

        auth = st.session_state.fmc_auth

        # Domain Selection
        if not st.session_state.fmc_domains:
            with st.spinner("Fetching domains..."):
                domains = auth.get_domains()
                if domains:
                    st.session_state.fmc_domains = domains
                else:
                    st.error("Failed to fetch domains.")

        if st.session_state.fmc_domains and not st.session_state.fmc_selected_domain:
            st.subheader("Select Domain")
            domain_options = {d.get('name'): d.get('uuid') for d in st.session_state.fmc_domains}
            selected_domain_name = st.selectbox("Available Domains", list(domain_options.keys()))
            if st.button("Select Domain"):
                domain_uuid = domain_options[selected_domain_name]
                auth.select_domain(domain_uuid)
                st.session_state.fmc_selected_domain = {"name": selected_domain_name, "uuid": domain_uuid}
                st.success(f"Selected domain: {selected_domain_name}")
                st.rerun()

        # Policy Operations
        if st.session_state.fmc_selected_domain:
            st.write(f"**Current Domain:** {st.session_state.fmc_selected_domain['name']}")
            st.subheader("Extract Policies")

            policy_types = {
                "Access Control Policies": "access",
                "NAT Policies": "nat",
                "Prefilter Policies": "prefilter",
                "SSL Policies": "ssl",
                "DNS Policies": "dns"
            }

            selected_type_name = st.selectbox("Select Policy Type", list(policy_types.keys()))
            policy_type = policy_types[selected_type_name]

            extractor = FMCPolicyExtractor(auth)

            if st.button("Fetch Policies"):
                with st.spinner(f"Fetching {selected_type_name}..."):
                    policies = extractor.get_policies(policy_type=policy_type)
                    if policies:
                        st.session_state.fmc_policies = policies
                        st.success(f"Found {len(policies)} policies.")
                    else:
                        st.session_state.fmc_policies = []
                        st.info(f"No {selected_type_name} found.")

            if st.session_state.fmc_policies:
                policy_options = {p.get('name'): p.get('id') for p in st.session_state.fmc_policies}
                selected_policy_name = st.selectbox("Select Policy to Extract Rules From", list(policy_options.keys()))

                if st.button("Extract Rules"):
                    policy_id = policy_options[selected_policy_name]
                    with st.spinner(f"Extracting rules for {selected_policy_name}..."):
                        # Extract rules based on type
                        rules = []
                        if policy_type == "access":
                            rules = extractor.get_access_rules(policy_id)
                        elif policy_type == "nat":
                            rules = extractor.get_nat_rules(policy_id)
                        elif policy_type == "prefilter":
                            rules = extractor.get_prefilter_rules(policy_id)
                        elif policy_type == "ssl":
                            rules = extractor.get_ssl_rules(policy_id)
                        elif policy_type == "dns":
                            rules = extractor.get_dns_rules(policy_id)

                        if rules:
                            st.success(f"Extracted {len(rules)} rules.")

                            # Simplify rules for display in a dataframe
                            display_data = []
                            progress_bar = st.progress(0)
                            for i, rule in enumerate(rules):
                                item = {
                                    "Rule Name": rule.get('name', ''),
                                    "Action": rule.get('action', ''),
                                    "Enabled": rule.get('enabled', True),
                                }
                                # Add some type specific stuff for the display
                                if policy_type == "access":
                                     src_zones = rule.get('sourceZones', {}).get('objects', [])
                                     item["Source Zones"] = ", ".join([z.get('name') for z in src_zones])
                                     dst_zones = rule.get('destinationZones', {}).get('objects', [])
                                     item["Dest Zones"] = ", ".join([z.get('name') for z in dst_zones])

                                display_data.append(item)
                                progress_bar.progress((i + 1) / len(rules))

                            df = pd.DataFrame(display_data)
                            st.dataframe(df, use_container_width=True)

                            csv = df.to_csv(index=False).encode('utf-8')
                            st.download_button(
                                label="Download CSV",
                                data=csv,
                                file_name=f"{selected_policy_name}_rules.csv",
                                mime="text/csv",
                            )
                        else:
                            st.info("No rules found in this policy.")

def cpapi_app():
    st.title("Check Point API (CP API) Integrator")

    if "cp_client" not in st.session_state:
        st.session_state.cp_client = None
    if "cp_server" not in st.session_state:
        st.session_state.cp_server = None

    if st.session_state.cp_client is None:
        st.subheader("Login to Check Point Management Server")
        st.info("Connections are initiated in read-only mode to prevent accidental modifications.")
        with st.form("cp_login_form"):
            server = st.text_input("Server IP or Hostname")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submit = st.form_submit_button("Login")

            if submit:
                if server and username and password:
                    with st.spinner("Connecting and authenticating..."):
                        try:
                            # Using 'unsafe=True' for lab environments or avoiding cert prompts
                            client_args = APIClientArgs(server=server, unsafe=True)
                            client = APIClient(client_args)

                            # IMPORTANT: Always use read-only mode as requested
                            login_res = client.login(username, password, read_only=True)

                            if login_res.success:
                                st.session_state.cp_client = client
                                st.session_state.cp_server = server
                                st.success("Successfully authenticated in Read-Only mode!")
                                st.rerun()
                            else:
                                st.error(f"Login failed: {login_res.error_message}")
                        except Exception as e:
                            st.error(f"Connection error: {str(e)}")
                else:
                    st.warning("Please fill in all fields.")
    else:
        st.success(f"Connected to Check Point Server at {st.session_state.cp_server} (Read-Only Mode)")
        if st.button("Logout", key="cp_logout"):
            st.session_state.cp_client = None
            st.session_state.cp_server = None
            st.rerun()

        st.divider()

        client = st.session_state.cp_client

        st.subheader("Read-Only Operations")
        operation = st.selectbox("Select Operation", ["Show Hosts", "Show Networks", "Show Policies"])

        if st.button("Execute"):
            with st.spinner(f"Executing {operation}..."):
                api_cmd = ""
                if operation == "Show Hosts":
                    api_cmd = "show-hosts"
                elif operation == "Show Networks":
                    api_cmd = "show-networks"
                elif operation == "Show Policies":
                    api_cmd = "show-access-rulebases"

                res = client.api_call(api_cmd, {"limit": 50, "details-level": "standard"})

                if res.success:
                    data = res.data
                    objects = data.get('objects', [])

                    if not objects:
                        st.info(f"No results found for {operation}.")
                    else:
                        st.success(f"Retrieved {len(objects)} items.")

                        display_data = []
                        for obj in objects:
                            item = {
                                "Name": obj.get('name', ''),
                                "Type": obj.get('type', ''),
                                "IPv4 Address": obj.get('ipv4-address', ''),
                                "Comments": obj.get('comments', '')
                            }
                            display_data.append(item)

                        df = pd.DataFrame(display_data)
                        st.dataframe(df, use_container_width=True)
                else:
                    st.error(f"API Call Failed: {res.error_message}")


def main():
    st.set_page_config(page_title="Network Security Config Extractor", layout="wide")

    st.sidebar.title("Navigation")
    module_selection = st.sidebar.radio("Select Module:", ["Firepower (FMC)", "Check Point (CP API)"])

    if module_selection == "Firepower (FMC)":
        fmc_app()
    elif module_selection == "Check Point (CP API)":
        cpapi_app()

if __name__ == "__main__":
    main()
