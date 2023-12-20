import asyncio
from pathlib import Path
import sys

import opaquepy as opq
from apiserver.data import Source, ops
import apiserver.lib.utilities as util
from apiserver import data
from apiserver.env import load_config
from auth.data.authentication import get_apake_setup
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


async def run_function(func_name):
    module = sys.modules['__main__']
    func = getattr(module, func_name)
    await func()

if __name__ == "__main__":
    function_to_run = sys.argv[1]

    asyncio.run(run_function(function_to_run))
