#!/usr/bin/env python3

from argparse import ArgumentParser
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from loguru import logger
from typing import Optional, Dict
import warnings
import base64
import http
import ipaddress
import os
import re
import requests

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

PASSWORD_DEFAULT = "456"
ADMIN_USERNAME = "Polycom"

def set_session_auth_cookie(session: requests.Session, username: str, password: str):
    # Set the Authorization HTTP header + cookie
    authstr = f"{username}:{password}"
    authstr = base64.b64encode(authstr.encode()).decode()
    session.auth = (username, password)
    session.cookies.set(
        name="Authorization",
        value=f"Basic {authstr}",
    )

def login(session: requests.Session, ip: str, username: str, password: str, suppress: bool = False) -> bool:
        # set cookie and auth header
        set_session_auth_cookie(session, username=username, password=password)

        r = session.get(f"http://{ip}/index.htm")
        if r.status_code != http.HTTPStatus.OK:
            if not suppress:
                logger.error(f"Invalid Password for '{ip}'")
            return False

        # authenticate
        r = session.post(f"http://{ip}/form-submit/auth.htm")
        if r.status_code == http.HTTPStatus.NOT_ACCEPTABLE:
            return True
        if r.status_code != http.HTTPStatus.OK or "|SUCCESS|" not in r.text:
            if not suppress:
                logger.error(f"Invalid authentication for '{ip}'")
            return False
        if not suppress:
            logger.success(f"Logged in to device '{ip}'")
        return True

def get_model(session: requests.Session, ip: str, r: requests.Response = None) -> Optional[str]:
    # if no response is provided, grab the index page
    if r is None:
        r = session.get(f"http://{ip}/index.htm")
        if r.status_code != http.HTTPStatus.OK:
            logger.error(f"Invalid Password for '{ip}'")
            return False
    model_values = list(set(re.findall(r"VVX (\d+)", r.text)))
    if not len(model_values):
        model_values = list(set(re.findall(r"Trio (\d+)", r.text)))
        if not len(model_values):
            return None
    model = model_values[0]
    logger.success(f"Device '{ip}' has hardware model '{model}'")
    return model

def get_csrf_token(session: requests.Session, ip: str, r: requests.Response = None) -> bool:
    # if no response is provided, grab the index page
    if r is None:
        r = session.get(f"http://{ip}/index.htm")
        if r.status_code != http.HTTPStatus.OK:
            logger.error(f"Invalid Password for '{ip}'")
            return False
    
    # find the CSRF token if it exists
    lines = r.text.splitlines()
    csrf_token = ""
    for line in lines:
        if "csrf-token" in line.lower():
            x = re.findall("content=\"(.*)\"", line)
            if not len(x) or not len(csrf_token := x[0]):
                logger.error(f"failed to extract CSRF token for device '{ip}'")
                return False
            logger.success(f"Found CSRF Token '{csrf_token}' for device '{ip}'")
            session.headers["anti-csrf-token"] = csrf_token
            break
    return True

def change_admin_password(ip: str, password_old: str, password_new: str):
    if password_old == password_new:
        logger.warning("the NEW and OLD passwords are identical")
        return True
    with requests.Session() as session:
        if not login(session, ip, "Polycom", password_old):
            return False
        if not get_csrf_token(session, ip):
            return False

        # change password
        form = {
            "oldadminpswd": password_old,
            "newadminpswd": password_new,
            "cnfmadminpswd": password_new,
        }
        r = session.post(f"http://{ip}/form-submit/Settings/ChangePassword", data=form)
        if r.status_code != http.HTTPStatus.OK:
            logger.error(f"Failed to change password for device '{ip}'")
            return False
        logger.success(f"Successfully changed password on device '{ip}'")
        return True

def change_admin_password_if_default(ip: str, password_new: str):
    with requests.Session() as session:
        if login(session, ip, "Polycom", PASSWORD_DEFAULT, suppress=True):
            logger.warning(f"Password is currently default for device '{ip}'. Resetting.")
            return change_admin_password(
                ip=ip,
                password_old=PASSWORD_DEFAULT,
                password_new=password_new,
            )
        else:
            logger.info(f"Password is not default for device '{ip}'")
            return True


def upgrade(ip: str, username: str, password: str, version_target_map: Dict[str, str], check_only: bool = False):
    server_type = "plcmserver"
    logger.info(f"Logging into IP '{ip}' with user '{username}'")
    with requests.Session() as session:
        if not login(session, ip, username, password):
            return False
        
        if not get_csrf_token(session, ip):
            return False
        
        model = get_model(session, ip)
        if (version_target := version_target_map.get(model)) is None:
            logger.error(f"Error on device '{ip}' invalid or unknown model '{model}'")
            return False

        # get the current version
        r = session.get(f"http://{ip}/Utilities/softwareUpgrade/getPhoneVersion")
        if r.status_code != http.HTTPStatus.OK:
            logger.error(f"Error on device '{ip}' (status code {r.status_code})")
            return False
        version_current = r.text
        if version_current == version_target:
            logger.success(f"Device '{ip}' is already on version {version_target}")
            return False
        logger.success(f"Device '{ip}' currently has version {version_current}")

        # get all available versions
        r = session.get(f"http://{ip}/Utilities/softwareUpgrade/getAvailableVersions?type={server_type}")
        if r.status_code != http.HTTPStatus.OK:
            logger.error(f"Error on device '{ip}' (status code {r.status_code})")
            return False
        soup = BeautifulSoup(r.content, "lxml")
        versions = dict()
        for phone_image in soup.find_all("phone_image"):
            versions[phone_image.version.text] = phone_image.path.text
        logger.info(f"Available versions: {list(versions.keys())}")
        if version_target not in versions:
            logger.error(f"Device '{ip}' does not contain version '{version_target}'")
            return False
        logger.success(f"Device '{ip}' is ready for version '{version_target}'")

        if check_only:
            logger.info(f"Device '{ip}' check-only. No upgrade performed.")
            return
        
        # submit upgrade
        form = {
            "URLPath": versions[version_target],
            "serverType": server_type,
        }
        r = session.post(f"http://{ip}/form-submit/Utilities/softwareUpgrade/upgrade", data=form, timeout=300)
        if r.status_code != http.HTTPStatus.OK:
            logger.error(f"Failed to upgrade device with code ({r.status_code})")
            return False
        logger.success(f"Successfully upgraded device '{ip}'. Rebooting shortly.")
        return True

def parse_ips(filename: str):
    ips = []
    with open(filename, "r") as fin:
        for line in fin:
            try:
                ips.append(str(ipaddress.ip_address(ip := line.strip())))
            except ValueError:
                logger.warning(f"Invalid IP '{ip}'")
                pass
    return ips


def main():
    ap = ArgumentParser()

    ap.add_argument("--file", "-f", type=str, required=True, help="File containing a list of Polycom Phone IPs")
    ap.add_argument("--password", "-p", type=str, default="4567", help="Non-default Polycom password to use")
    ap.add_argument("--check", "-c", action="store_true", help="Check Only (Do Not Perform Upgrade)")
    ap.add_argument("--model500", type=str, default="5.9.7.3480", metavar="<VVX 500 FIMRWARE VERSION>", help="Firmware version for VVX 500")
    ap.add_argument("--model501", type=str, default="5.9.7.4477", metavar="<VVX 501 FIRMWARE VERSION>", help="Firmware version for VVX 501")
    ap.add_argument("--model8500", type=str, default="7.2.2.1094", metavar="<Trip 8500 FIRMWARE VERSION>", help="Firmware version for Trio 8500")

    args = ap.parse_args()

    if args.password == PASSWORD_DEFAULT:
        ap.error(f"--password must not be Polycom default ('{PASSWORD_DEFAULT}')")
    
    if not os.path.isfile(args.file):
        ap.error(f"file '{args.file}' does not exist")

    password = args.password
    version_map = {
        "500": args.model500,
        "501": args.model501,
        "8500": args.model8500,
    }

    ips = parse_ips(args.file)
    if len(ips) == 0:
        ap.error("no valid IP's were found")
    
    for ip in ips:
        try:
            # Ensure the admin password is not defalt
            if not change_admin_password_if_default(ip=ip, password_new=password):
                logger.warning(f"Skipping device '{ip}'")
                continue

            # perform the firmware upgrade
            upgrade(ip, ADMIN_USERNAME, password, version_map, check_only=args.check)
        except Exception as e:
            logger.exception(e)


if __name__ == "__main__":
    main()
