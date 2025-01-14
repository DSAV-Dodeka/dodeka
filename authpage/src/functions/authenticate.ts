import {client_register_wasm, client_register_finish_wasm, client_login_wasm, client_login_finish_wasm} from "@tiptenbrink/opaquewasm";
import config from "../config";
import {RegisterState} from "../credentials/register/Register";
import {back_post, catch_api} from "./api";
import {z} from "zod";
import ky, { HTTPError, KyResponse } from "ky";

const OpaqueResponse = z.object({
    server_message: z.string(),
    auth_id: z.string()
})

interface VoltaRegistration {
    AddressInfo: {
        countryId: 528,
        zipcode: string,
        city: string,
        address1: string,
        houseNumber: number
    },
    BillingInfoDto: {
        debtCollection: true,
        iban: string,
        bankAccountName: string
    },
    PlanAssignment: Plan["PlanAssignment"],
    FirstName: string,
    LastName: string,
    Initials: string,
    Gender: 0 | 1 | 2,
    Birthdate: string,
    Email: {
        Email: string
    },
    MobilePhone: {
        Number: string
    }
    LanguageCode: "nl-NL" | "en-GB",
    selectedPlan: Plan["selectedPlan"]
}

interface Plan {
    PlanAssignment: {
        startDate: string,
        planId: number
    },
    selectedPlan: PlanDetails & { startDate: string, endDate: string }
}

interface PlanDetails {
    price: 60 | 50 | 30;
    planCode: string;
    registrationFee: 5;
    remittanceFee: null;
    transferFee: 0;
    discountFee: 0;
    administrationFee: null;
    remittanceDescription: null;
    fromAge: 0;
    toAge: 99;
    referenceDate: null; // ISO 8601 date string or null
    organisationTypeIds: [];
    id: number;
    name: string;
}

const wedstrijdlidPlan: PlanDetails = {
    price: 60,
    planCode: "12",
    registrationFee: 5,
    remittanceFee: null,
    transferFee: 0,
    discountFee: 0,
    administrationFee: null,
    remittanceDescription: null,
    fromAge: 0,
    toAge: 99,
    referenceDate: null,
    organisationTypeIds: [],
    id: 11286,
    name: "Wedstrijdlid"
};

const recreantPlan: PlanDetails = {
    price: 50,
    planCode: "13",
    registrationFee: 5,
    remittanceFee: null,
    transferFee: 0,
    discountFee: 0,
    administrationFee: null,
    remittanceDescription: null,
    fromAge: 0,
    toAge: 99,
    referenceDate: null,
    organisationTypeIds: [],
    id: 11287,
    name: "Recreant lid"
};

const gastPlan: PlanDetails = {
    price: 30,
    planCode: "14",
    registrationFee: 5,
    remittanceFee: null,
    transferFee: 0,
    discountFee: 0,
    administrationFee: null,
    remittanceDescription: null,
    fromAge: 0,
    toAge: 99,
    referenceDate: null,
    organisationTypeIds: [],
    id: 11288,
    name: "Gastlid"
};

function registerStateToVolta(registerState: RegisterState): VoltaRegistration {
    let planDetails: PlanDetails;
    if (registerState.plan === "Wedstrijdlid") {
        planDetails = wedstrijdlidPlan
    } else if (registerState.plan === "Recreantlid") {
        planDetails = recreantPlan
    } else if (registerState.plan === "Gastlid") {
        planDetails = gastPlan
    } else {
        throw new Error(`Unknown plan ${registerState.plan}!`)
    }

    // FIXME make next quarter
    const planAssignmentStartDate = "2025-01-01T00:00:00.001Z"
    const planStartDate = "2024-10-01T00:00:00"
    const planEndDate = "2025-09-30T00:00:00"

    const plan: Plan = {
        selectedPlan: {
            ...planDetails,
            startDate: planStartDate,
            endDate: planEndDate
        },
        PlanAssignment: {
            planId: planDetails.id,
            // FIXME check if this is indeed supposed to be different
            startDate: planAssignmentStartDate
        }
    }

    const genderParsed = parseInt(registerState.gender)
    let gender: VoltaRegistration["Gender"];
    if (genderParsed === 0 || genderParsed === 1 || genderParsed === 2) {
        gender = genderParsed
    } else {
        throw new Error("Invalid gender!")
    }

    let language: VoltaRegistration["LanguageCode"];
    if (registerState.language === "nl-NL" || registerState.language === "en-GB") {
        language = registerState.language
    } else {
        throw new Error("Invalid language!")
    }

    return {
        ...plan,
        AddressInfo: {
            countryId: 528,
            zipcode: registerState.zipcode,
            city: registerState.city,
            address1: registerState.address,
            houseNumber: parseInt(registerState.house_number)
        },
        BillingInfoDto: {
            debtCollection: true,
            iban: registerState.iban,
            bankAccountName: registerState.iban_name
        },
        FirstName: registerState.firstname,
        LastName: registerState.lastname,
        Initials: registerState.initials,
        Gender: gender,
        Birthdate: registerState.date_of_birth,
        Email: {
            Email: registerState.email
        },
        MobilePhone: {
            Number: registerState.phone
        },
        LanguageCode: language
    }
}

const volta = ky.create({prefixUrl: "https://prod.foys.tech/api/v2/pub/registration-forms/4717c5a6-5e49-4d4d-ca49-08dd2f2dfc8c/"});

export class VoltaError extends Error {
    constructor(detail: string) {
        super(`Volta returnedd error with detail: ${detail}`)
        this.voltaMessage = detail
    }

    voltaMessage: string;
}

async function doVoltaRegister(voltaRegistration: VoltaRegistration) {
    let result: KyResponse;
    try {
        result = await volta.post("", { json: voltaRegistration })
    }
    catch (e) {
        if (e instanceof HTTPError) {
            const result = e.response
            console.log(`result.status=${result.status}\ncontent-type=${(result.headers.get('Content-Type') ?? '')}`)
            if (result.status === 400 && (result.headers.get('Content-Type') ?? '').includes('json')) {
                const jsonParsed = await result.json()
                console.log(`jsonParsed=${JSON.stringify(jsonParsed)}.`)
                if (typeof jsonParsed === 'object' && jsonParsed !== null && 'detail' in jsonParsed) {
                    throw new VoltaError(String(jsonParsed.detail))
                }
            }

            throw new Error(`Failed to register with Volta: Result:\n${await result.text()}`)
        }
        throw e
    }

    if (result.status !== 200) {
        throw new Error(`Volta registration failed with status=${result.status} and content:\n${await result.text()}`)
    }
}

export async function clientRegister(registerState: RegisterState) {
    const voltaRegistration = registerStateToVolta(registerState)

    await doVoltaRegister(voltaRegistration)

    try {
        const state = client_register_wasm(registerState.password)

        const register_start = {
            email: registerState.email,
            firstname: registerState.firstname,
            lastname: registerState.lastname,
            client_request: state.message,
        }
        const res = await back_post("onboard/register/", register_start)
        const {server_message, auth_id} = OpaqueResponse.parse(res)

        const client_request = client_register_finish_wasm(state, registerState.password, server_message)
 
        const register_finish = {
            firstname: registerState.firstname,
            lastname: registerState.lastname,
            client_request,
            auth_id,
            birthdate: registerState.date_of_birth,
            joined: "2025-01-01",
            age_privacy: registerState.birthday_check
        }
        await back_post("onboard/finish/", register_finish)
        return true

    } catch (e) {
        console.log(e)
        return false
    }
}

export async function passUpdate(email: string, flow_id: string, password: string) {
    try {
        const state = client_register_wasm(password)

        const register_start = {
            "email": email,
            "client_request": state.message,
            "flow_id": flow_id
        }
        const res = await back_post("update/password/start/", register_start)
        const {server_message, auth_id} = OpaqueResponse.parse(res)

        const message2 = client_register_finish_wasm(state, password, server_message)

        const register_finish = {
            "client_request": message2,
            "auth_id": auth_id,
        }

        await back_post("update/password/finish/", register_finish)
        return true

    } catch (e) {
        console.log(e)
        return false
    }
}

export async function clientLogin(username: string, password: string, flow_id: string) {
    try {
        const state = client_login_wasm(password)

        // get message to server and get message back
        const login_start = {
            "email": username,
            "client_request": state.message
        }
        const res = await back_post("login/start/", login_start)
        const {server_message, auth_id} = OpaqueResponse.parse(res)

        // pass 'abc'
        //const login_state = "Gg6GSd_2X9ccTkVZBatUyynmRM5CWBVh9j8Fsac2hQAAYoxXlNs3YTKM_4eq-Tr3hOM5TO1OZTaAgI7DYQIV4rhX-EomurCCwcw3cojfbBudPS6aF0YyxJZYbjgD8ABTigIAAMaJ77uRiMGm50uF6_VEFchFlKmwvKhhiUUsRhZhRl1fAEChX0fsJTWoEsS2bPTSt-1BKlRkL85rlA1yZkr56BWbCvhKJrqwgsHMN3KI32wbnT0umhdGMsSWWG44A_AAU4oCYWJj"
        //const server_message = "ho_5N1Kup16z2J_aoR3MxLpxrM--gE-AFLz8-bhkIh_8cilJ2k3wlBxI5tG-aPV_-VNMoit3BFUK-8zO6cYpdAETrMqI8STeP2akP4qAmQ8A5nAFshWJUpU3NfznjqXFTFPMQRJAaV9Ga-xnDUXd7KTkW18gQeoI_QWXN9xgYaFJHsYTVOYXoWKkoOwbHfurl9tNesy7DhgOnFvBH7rxH3-i3Xcl4lPuHtFFlgNCLwR4r1V0wH9tFSGC30LmXpZOBLWWZ0IXIl5BBZ5mSCJJHS9UKiYIYAHjsDjpeMQaRm_0PA70Xqrlk1dLmlhrWSoX46pZQ3Bxp2bKxF38mtr3MQcAAO3RwD2P-EutfATHdQ2W1qQZuJyOjG255FSAsbBLIOFBcpYBCNIitdoxYe7baP6gI_A9LxyK4kP0kOXg17sQ8wQ="
        //const server_message = "GjLrN4JEUsjQgmesadkoPWbOblKFA2B_fbgFclxoW03GVBmt60hTg5I8TzpcuB6VAZffJkgztbfI5pETN-l-WAHbuTdN1azA6NI6d-oP3TOm-_sVanwq2zE35LJAMHhXQDdLpf3YxY3OCZfMCDfjz4hC8yU9KR4kawwKnnVj8cI_DjUG2M7pFJAR5VJ1j5yYmERTn_8S_vzxm6M6y0FGARx_J8HcjATeNkdiS9DCtte-1vCZa0UnhOpOf4IEEHl3AJ71NBsDbp8kEI4GanzhH3bPCqoWukPT_MToVe1pbROJkCKaxKwBu1PuMbF4e-hw4EtQuCJmb5l6-Zm7SkowBVYAAPfgo_zRAhkBivXxX0t0H33plYrN_7yKaDZIZiCMMyiuYabsvs_op4JKgD2hV-X1PPpUdrMZ-WVrZstLRiqr2_E="

        const { message: message2, shared_secret } = client_login_finish_wasm(state, password, server_message)

        const login_finish = {
            "email": username,
            "client_request": message2,
            "auth_id": auth_id,
            "flow_id": flow_id
        }

        await back_post("login/finish/", login_finish)
        return shared_secret

    } catch (e) {
        if (e instanceof Error && e.name === "InvalidLogin") {
            console.log("IsError")
            console.log(e.message)
        }
        else {
            const err = catch_api(e)
            console.log(err)
        }
        return null
    }
}