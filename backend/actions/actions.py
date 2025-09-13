import asyncio
from pathlib import Path
import sys

from apiserver.data import Source, ops
from apiserver import data
from apiserver.data.api.ud.userdata import new_userdata
from apiserver.lib.model.entities import SignedUp
from auth.data.relational.opaque import get_setup
from faker import Faker

import opaquepy as opq

import apiserver.lib.utilities as util
import auth.core.util
from apiserver.app.ops.startup import get_keystate
from apiserver.define import DEFINE
from apiserver.settings import load_config
from auth.data.authentication import get_apake_setup
from auth.data.keys import get_keys
from auth.data.relational.user import EmptyIdUserData
from auth.define import refresh_exp, access_exp, id_exp
from auth.token.build import create_tokens, finish_tokens
from datacontext.context import DontReplaceContext
from store import Store


def get_api_config():
    test_config_path = Path(__file__).parent.joinpath("localdead.toml")
    return load_config(test_config_path)


async def get_local_dsrc():
    api_config = get_api_config()
    store = Store()
    store.init_objects(api_config)
    dsrc = Source()
    dsrc.store = store
    await store.startup()
    return dsrc


async def admin_access():
    local_dsrc = await get_local_dsrc()
    admin_id = "admin_test"
    scope = "member admin"
    utc_now = auth.core.util.utc_timestamp()
    id_userdata = EmptyIdUserData()
    access_token_data, id_token_data, access_scope, refresh_save = create_tokens(
        admin_id,
        scope,
        utc_now - 1,
        "test_nonce",
        utc_now,
        id_userdata,
        DEFINE.issuer,
        DEFINE.frontend_client_id,
        DEFINE.backend_client_id,
        refresh_exp,
    )
    refresh_id = 5252626
    key_state = await get_keystate(local_dsrc)
    keys = await get_keys(DontReplaceContext(), local_dsrc.store, key_state)
    refresh_token, access_token, id_token = finish_tokens(
        refresh_id,
        refresh_save,
        keys.symmetric,
        access_token_data,
        id_token_data,
        id_userdata,
        utc_now,
        keys.signing,
        access_exp,
        id_exp,
        nonce="",
    )
    return access_token


async def set_pw():
    local_dsrc = await get_local_dsrc()
    admin_password = "admin"
    setup = await get_apake_setup(DontReplaceContext(), local_dsrc.store)

    cl_req, cl_state = opq.register_client(admin_password)
    serv_resp = opq.register(setup, cl_req, util.usp_hex("0_admin"))
    cl_fin = opq.register_client_finish(cl_state, admin_password, serv_resp)
    pw_file = opq.register_finish(cl_fin)

    async with data.get_conn(local_dsrc) as conn:
        await ops.user.update_password_file(conn, util.usp_hex("0_admin"), pw_file)

    print("set admin password to 'admin'.")


async def print_admin_token():
    admin_token = await admin_access()
    print(admin_token)


async def generate_dummies():
    local_dsrc = await get_local_dsrc()
    faker = Faker()
    admin_password = "admin"
    async with data.get_conn(local_dsrc) as conn:
        setup = await get_setup(conn)

    # setup = ""
    faker_u = faker.unique

    for i in range(99):
        fname = faker_u.first_name()
        lname = faker_u.last_name()
        email = f"{fname}.{lname}@gmail.com"
        su = SignedUp(
            firstname=fname,
            lastname=lname,
            email=email,
            # phone=faker_u.phone_number(),
            # confirmed=True,
        )
        joined = faker.date()
        async with data.get_conn(local_dsrc) as conn:
            uid = await data.user.new_user(
                conn,
                su,
                # register_id=register_id,
                # av40id=av40id,
                # joined=joined,
            )

            cl_req, cl_state = opq.register_client(admin_password)
            serv_resp = opq.register(setup, cl_req, uid)
            cl_fin = opq.register_client_finish(cl_state, admin_password, serv_resp)
            pw_file = opq.register_finish(cl_fin)
            birthdate = faker.date()
            userdata = new_userdata(su, uid, joined, birthdate)
            await data.user.UserOps.update_password_file(conn, uid, pw_file)
            did_ups = await data.ud.upsert_userdata(conn, userdata)
            print(did_ups)


async def run_function(func_name):
    module = sys.modules["__main__"]
    func = getattr(module, func_name)
    await func()


if __name__ == "__main__":
    function_to_run = sys.argv[1]

    asyncio.run(run_function(function_to_run))
