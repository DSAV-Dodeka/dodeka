import React, {
    useReducer,
    Suspense,
    FormEvent,
    ChangeEvent,
    FocusEvent,
    useState,
    useEffect,
    MouseEvent,
    useRef
} from "react";
import "./Register.scss";
import "../../index.scss";
import config from "../../config";
import {clientLogin, clientRegister, VoltaError} from "../../functions/authenticate";
import {base64ToBin} from "../../functions/encode";
import Back from "../../components/Back";
import {z} from "zod";
import {new_err} from "../../functions/error";
import Logo from "../../logo.svg?react"
import Title from "../../components/Title";
// Imported lazily due to large library size
const PasswordStrength = React.lazy(() => import('../../components/PasswordStrength'));

const registerReducer = (state: RegisterState, action: RegisterAction): RegisterState => {
    switch (action.type) {
        case 'reload':
            return action.new_state
        case 'change': // Both 'change' and 'change_bool' have same effect
        case 'change_bool':
            return {
                ...state,
                [action.field]: action.value
            }
        default:
            throw new Error()
    }

}

export type RegisterState = {
    firstname: string,
    lastname: string,
    initials: string,
    email: string,
    phone: string,
    zipcode: string,
    city: string,
    address: string,
    house_number: string,
    password: string,
    password_confirm: string,
    date_of_birth: string,
    enable_incasso: boolean,
    iban: string,
    iban_name: string,
    gender: string,
    birthday_check: boolean,
    student: boolean,
    plan: string,
    eduinstitution: string,
    eduinstitution_other: string,
    language: string,
}

type RegisterAction =
    | { type: 'reload', new_state: RegisterState}
    | { type: 'change', field: string, value: string }
    | { type: 'change_bool', field: string, value: boolean }

let initialState: RegisterState = {
    firstname: "",
    lastname: "",
    initials: "",
    email: "",
    phone: "",
    zipcode: "",
    city: "",
    address: "",
    house_number: "",
    password: "",
    password_confirm: "",
    date_of_birth: "",
    enable_incasso: false,
    iban: "",
    iban_name: "",
    gender: "male",
    birthday_check: false,
    student: false,
    plan: "Wedstrijdlid",
    eduinstitution: "TU Delft",
    eduinstitution_other: "",
    language: ""
}

let focus:boolean = false;

const handleFocus = (event: FocusEvent<HTMLInputElement>) => {
    if (!focus) {
        event.target.blur();
        event.target.type = 'date';
        focus = true;
        clearTimeout(0);
        event.target.focus();
    }
}

const handleBlur = (event: FocusEvent<HTMLInputElement>) => {
    if (focus) {
        event.target.type = 'text';
        focus = false;
    }
}

const redirectUrl = `${config.client_location}/registered`

const Register = () => {
    const myStatus = useRef<HTMLDivElement>(null)
    const [handled, setHandled] = useState(false)
    const [infoOk, setInfoOk] = useState(false)
    const [state, dispatch] = useReducer(
        registerReducer,
        initialState,
    )
    const [submitted, setSubmitted] = useState("")
    const [passScore, setPassScore] = useState(0)
    const [status, setStatus] = useState("\u00A0")


    useEffect(() => {
        if (!handled) {
            try {
                const reducerInitial = { ...initialState }
                setInfoOk(true)
                dispatch({type: 'reload', new_state: reducerInitial})
            } catch (e) {
                setInfoOk(false)
            }
            setHandled(true)
        }
    }, [handled]);

    const somethingWrong = () => {
        setStatus("Er is iets misgegaan!")
    }

    const formIsValid = () => {
        if (passScore < 2) {
            setStatus("Je wachtwoord is te zwak, maak het langer of onregelmatiger.")
            return false;
        }
        else if (state.password != state.password_confirm) {
            setStatus("De wachtwoorden zijn niet gelijk.")
            return false;
        }
        setStatus("")
        return true;
    }

    const handleSubmit = (e: FormEvent) => {
        e.preventDefault()

        if (formIsValid()) {
            var eduinstitution;
            if (!state.student) {
                eduinstitution = "";
            } else {
                eduinstitution = state.eduinstitution === "Anders, namelijk:" 
                    ? state.eduinstitution_other 
                    : state.eduinstitution;
            }
            const submitState = { ...state, eduinstitution }

            clientRegister(submitState).then(
                (result) => {
                    if (result) {
                        window.location.assign(redirectUrl)
                    } else {
                        console.log(new_err("bad_register", "Bad register result!", "register_false").j())
                        somethingWrong()
                    }
                },
                (e) => {
                    console.log(e)

                    if (e instanceof VoltaError) {
                        setStatus(e.voltaMessage)
                    } else {
                        somethingWrong()
                    }

                    if (myStatus.current !== null) {
                        myStatus.current.scrollIntoView()
                    }
                }
            )
        }
    }

    const handleSubmitClick = () => {
        setSubmitted("submitted")
    }

    const handleFormChange = (event: ChangeEvent<HTMLInputElement>) => {
        const { name, value } = event.target
        dispatch({type: 'change', field: name, value})
    }

    const handleSelectChange = (event: ChangeEvent<HTMLSelectElement>) => {
        const { name, value } = event.target
        dispatch({type: 'change', field: name, value})
    }

    const handleCheckboxChange = (event: ChangeEvent<HTMLInputElement>) => {
        const { name, checked } = event.target
        dispatch({type: 'change_bool', field: name, value: checked});
    }

    return (
        <div className="backend_page">
            <Back />
            <Title title="Registeren" />
            {!infoOk && handled &&
            <p className="largeText">Deze link voor het registratieformulier werkt niet, probeer het opnieuw of vraag het bestuur om een nieuwe link!</p>
            }
            {infoOk &&
            <form className="form" onSubmit={handleSubmit}>
                <div className={"dropdown"}>
                    <label >Taal/Language:</label>
                    <select id="language" name="language" value={state.language}
                            onChange={handleSelectChange}>
                        <option value="nl-NL">Nederlands</option>
                        <option value="en-GB">English/Other</option>
                    </select>
                </div>
                <input className={submitted} required id="firstname" type="text" placeholder="Voornaam" name="firstname" value={state.firstname}
                       onChange={handleFormChange}/>
                <input className={submitted} required id="lastname" type="text" placeholder="Achternaam" name="lastname" value={state.lastname}
                       onChange={handleFormChange}/>
                <input className={submitted} required id="initials" type="text" placeholder="Initialen" name="initials" value={state.initials}
                       onChange={handleFormChange}/>
                <div className={"dropdown"}>
                    <label >Geslacht:</label>
                    <select id="gender" name="gender" value={state.gender}
                            onChange={handleSelectChange}>
                        <option value="0">Man</option>
                        <option value="1">Vrouw</option>
                        <option value="2">Anders</option>
                    </select>
                </div>
                <input className={submitted} required id="email" type="text" placeholder="E-mail" name="email" value={state.email}
                       onChange={handleFormChange}/>
                <input className={submitted} required id="phone" type="text" placeholder="Telefoonnummer" name="phone" value={state.phone}
                       onChange={handleFormChange}/>
                <input required className={"formPassword " + submitted}  id="password" type="password" placeholder="Wachtwoord" name="password" value={state.password}
                       onChange={handleFormChange}/>
                {/** The Suspense is used because the library used for loading is quite big, so it is loaded in the background after page load **/}
                <Suspense fallback={<div className="passBar1">""</div>}><PasswordStrength password={state.password} passScore={passScore} setPass={setPassScore}/></Suspense>
                <input className={submitted} required id="password_confirm" type="password" placeholder="Herhaal wachtwoord" name="password_confirm" value={state.password_confirm}
                       onChange={handleFormChange}/>
                <div className="dropdown">
                <input className={submitted} required id="zipcode" type="text" placeholder="Postcode" name="zipcode" value={state.zipcode}
                       onChange={handleFormChange}/>
                <input className={submitted} required id="city" type="text" placeholder="Plaats" name="city" value={state.city}
                       onChange={handleFormChange}/>
                <input className={submitted} required id="address" type="text" placeholder="Straat" name="address" value={state.address}
                       onChange={handleFormChange}/>
                <input className={submitted} required id="house_number" type="text" placeholder="Huisnummer" name="house_number" value={state.house_number}
                       onChange={handleFormChange}/>
                <label>Geboortedatum:</label>
                <input className={submitted} required id="date_of_birth" type="date" placeholder="Geboortedatum" name="date_of_birth" value={state.date_of_birth}
                        onChange={handleFormChange} />
                </div>
                <div className={"dropdown"}>
                    <label>Soort lidmaatschap:</label>
                    <select id="plan" name="plan" value={state.plan}
                            onChange={handleSelectChange}>
                        <option value="Wedstrijdlid">Wedstrijdlid (€60 per kwartaal)</option>
                        <option value="Recreantlid">Recreantlid (€50 per kwartaal)</option>
                        <option value="Gastlid">Gastlid (€30 per kwartaal)</option>
                    </select>
                </div>
                <div className="checkbox">
                    <label >Automatische incasso en akkoord €5 registratiekosten</label>
                    <input required id="enable_incasso" type="checkbox" name="enable_incasso" checked={state.enable_incasso}
                            onChange={handleCheckboxChange}/>
                </div>
                <input className={submitted} required id="iban" type="text" placeholder="IBAN" name="iban" value={state.iban}
                       onChange={handleFormChange}/>
                <input className={submitted} required id="iban_name" type="text" placeholder="Naam op rekening" name="iban_name" value={state.iban_name}
                       onChange={handleFormChange}/>
                <div className="checkbox">
                    <label >Leden mogen mijn verjaardag en leeftijd zien</label>
                    <input className={submitted} id="birthday_check" type="checkbox" name="birthday_check" checked={state.birthday_check}
                            onChange={handleCheckboxChange}/>
                </div>
                <div className="checkbox">
                    <label >Ik ben student</label>
                    <input id="student" type="checkbox" name="student" checked={state.student}
                            onChange={handleCheckboxChange}/>
                </div>

                <div className={"dropdown" + (state.student ? "": " inputHidden")}>
                    <label >Onderwijsinstelling:</label>
                    <select id="eduinstitution" name="eduinstitution" value={state.eduinstitution}
                            onChange={handleSelectChange}>
                        <option>TU Delft</option>
                        <option>Haagse Hogeschool - Delft</option>
                        <option>Haagse Hogeschool - Den Haag</option>
                        <option>Hogeschool Inholland - Delft</option>
                        <option>Anders, namelijk:</option>
                    </select>
                </div>
                <input className={"" + (state.student && state.eduinstitution === "Anders, namelijk:" ? "" : " inputHidden")} id="eduinstitution_other" type="text" placeholder="Onderwijsinstelling" name="eduinstitution_other" value={state.eduinstitution_other}
                        onChange={handleFormChange} />

                <br />
                <button className="authButton" id="submit_button" onClick={handleSubmitClick} type="submit">Registreer</button><br />
                <p className="buttonText">Door op registeer te klikken ga je akkoord met het eerder genoemde <a href="https://dsavdodeka.nl/files/privacyverklaring_dodeka_jan23.pdf" target="_blank" rel="noreferrer" className="privacy_link">privacybeleid</a></p>
                <div ref={myStatus} id="status" className="formStatus">{status.length > 0 ? <span><strong>Error:</strong> {status}</span> : ''}</div>
            </form>}
        </div>
    )
}

export default Register;