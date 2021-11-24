
import * as _ from "lodash";
import initFx = require("../servidor/inicializar");
const admin = initFx.adminFirebase;
const firestore = initFx.firestoreOpts;

type _definedLevel = (1 | 2 | 3 | 4 | 5);

/**
 * Basic function that allows me to protect my API (POST | PUT | PATCH).
 * Blocking unnecessary calls to my API that intend to make harmful or unauthorized changes to my resources.
 *
 * @param {object} apiMethod
 * The type of method by which my API will be called will be
 * defined and the method by which the user executes the call will be attached.
 * @example
 * "API POST call accepted"
 * { _definedMethod: "POST", userValue: "POST" } return "The method defined and the method performed by the user coincide."**
 *
 * "API PUT call rejected"
 * { _definedMethod: "PUT", userValue: "PATCH" } return "The method defined and the method performed by the user do not match."**
 *
 * **"The shown examples of returns do not follow the established definitions, for more information see the RETURNS section."
 *
 * @param {object} apiType
 * We define if the API is public or private, in which the public one does not need the TOKEN of the user and in the private one it is necessary to export the TOKEN of the user,
 * as well as we must also define the LEVEL of authorized access and the allowed seconds of expiration of the TOKEN based on the hour of the FIREBASE.
 * @example
 * "PUBLIC API"
 * { _definedType: false }
 *
 * "PRIVATE API: Only a level 4 user is allowed access to the API and their token must be no more than 10 seconds old."
 * { _definedType: true, _definedSeconds: 10, _definedLevel: [4], userToken: "EXAMPLE_TOKEN" }
 *
 * @param {object} apiParams We declare the part of the parameters that the API must contain, and export the parameters of the call by the user.
 * @example
 * "The parameters ARE necessary for the API"
 * {required: true, _definedParams: string[], userValue: {nameParam: string, valueParam: any[]}
 *
 * "The parameters ARE NOT required for the API"
 * {requires: false}
 *
 * // API call accepted
 * {required: true, _definedParams: ["uid", "center"], userValue: [{nameParam: "uid", valueParam: "a1b2c3"}, {nameParam: "center", valueParam: "center-001"}]}
 * return "Defined parameters match user parameters"**
 *
 * // API call rejected
 * {requires: true, _definedParams: ["uid", "center"], userValue: [{nameParams: "uid", valueParams: undefined}, {nameParams: "center", valueParams: "center-001"}]}
 * return "UID parameter does not match the parameter defined by the API"**
 *
 * **"The shown examples of returns do not follow the established definitions, for more information see the RETURNS section."
 *
 * @param {object} apiBody We declare the part of the body that should contain the API, and export the body of the call by the user.
 * @example
 * * "The body IS required for the API"
 * {required: true, _definedBody: string[], userValue: {nameBody: string, valueBody: any[]}
 *
 * "The body IS NOT required for API"
 * {requires: false}
 *
 * // API call accepted
 * {_definedBody: ["uid", "center"], userValue: [{nameBody: "uid", valueBody: "a1b2c3"}, {nameBody: "center", valueBody: "center-001"}]}
 * return "The defined body matches the user's body."**
 *
 * // API call rejected
 * {_definedBody: ["uid", "center"], userValue: [{nameBody: "uid", valueBody: undefined}, {nameBody: "center", valueBody: "center-001"}]}
 * return "The defined body does not match the user's body."
 *
 * **"The shown examples of returns do not follow the established definitions, for more information see the RETURNS section."
 *
 * @return {{status: number, code: string, subcode: number, devDescription: string}}
 * Returns whether or not it is possible to execute the function.
 *
 * @example
 * // API call accepted (201) - UNIQUE
 * return { status: 201, code: "x19f-S/S/securityLayer", subcode: 0, devDescription: "API has successfully passed all defined security guidelines." }
 *
 * // API call rejected (400) - 6 different responses
 * return { status: 400, code: "x1f-S/S/securityLayer", subcode: 1, devDescription: "API was not called by the previously defined method" };
 * return { status: 400, code: "x1f-S/S/securityLayer", subcode: 2, devDescription: "API does not contain TOKEN header" }
 * return { status: 400, code: "x1f-S/S/securityLayer", subcode: 3, devDescription: "User TOKEN is invalid.." };
 * return { status: 400, code: "x1f-S/S/securityLayer", subcode: 4, devDescription: "User's TOKEN expired " + timeRemaining + " seconds ago." };
 * return { status: 400, code: "x1f-S/S/securityLayer", subcode: 5, devDescription: "The PARAMETERS of the user call do not contain the PARAMETERS defined by the API." };
 * return { status: 400, code: "x1f-S/S/securityLayer", subcode: 6, devDescription: "The body of the user call does not contain the body defined by the API." };
 *
 * // API call rejected (401) - UNIQUE
 * return { status: 401, code: "x1f-S/S/securityLayer", subcode: 0, devDescription: "The user LEVEL is different from the LEVEL defined by the API. User LEVEL: " + levelUser }
 *
 */
export async function securityLayer(
    apiMethod: {
        _definedMethod: "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
        userValue: string
    },
    apiType: { _definedType: false } |
    {
        _definedType: true,
        _definedSeconds: number,
        _definedLevel: _definedLevel[],
        userToken: string | undefined
    },
    apiParams: { required: false } |
    {
        required: true,
        _definedParams: string[],
        userParams: { nameBody: string, valueBody: any }[]
    },
    apiBody: { required: false } |
    {
        required: true,
        _definedBody: string[],
        userBody: { nameBody: string, valueBody: any }[]
    }
): Promise<{ status: number, code: string, subcode: number, devDescription: string }> {
    if (apiMethod.userValue !== apiMethod._definedMethod) {
        return {
            status: 400,
            code: "x1f-S/S/securityLayer",
            subcode: 1,
            devDescription:
                "API was not called by the previously defined method",
        };
    } else {
        if (!apiType._definedType) {
            // Public API
            if (apiParams.required) {
                for (const iterator of apiParams._definedParams) {
                    const item = apiParams.userParams.find((item) => item.nameBody === iterator);
                    if (item?.valueBody === null) {
                        return {
                            status: 400,
                            code: "x1f-S/S/securityLayer",
                            subcode: 5,
                            devDescription:
                                "The PARAMETERS of the user call do not contain the PARAMETERS defined by the API.",
                        };
                    }
                }
            }

            if (apiBody.required) {
                for (const iterator of apiBody._definedBody) {
                    const item = apiBody.userBody.find((item) => item.nameBody === iterator);
                    if (item?.valueBody === null) {
                        return {
                            status: 400,
                            code: "x1f-S/S/securityLayer",
                            subcode: 6,
                            devDescription:
                                "The BODY of the user call does not contain the BODY defined by the API.",
                        };
                    }
                }
            }

            return {
                status: 201,
                code: "x19f-S/S/securityLayer",
                subcode: 0,
                devDescription:
                    "API has successfully passed all defined security guidelines.",
            };
        } else {
            // Private API
            if (apiType.userToken === undefined) {
                return {
                    status: 400,
                    code: "x1f-S/S/securityLayer",
                    subcode: 2,
                    devDescription:
                        "API does not contain TOKEN header",
                };
            } else {
                return await admin.auth().verifyIdToken(apiType.userToken).then((decodedToken) => {
                    const _definedTime = apiType._definedSeconds;
                    const timeServer = firestore.Timestamp.now();
                    const timeUser = decodedToken.iat;
                    const _definedLevel = apiType._definedLevel;
                    const levelUser = decodedToken.lvl;

                    if (timeServer.seconds - timeUser > _definedTime) {
                        const timeRemaining = timeServer.seconds - timeUser - _definedTime;
                        return {
                            status: 400,
                            code: "x1f-S/S/securityLayer",
                            subcode: 4,
                            devDescription:
                                "User's TOKEN expired " + timeRemaining + " seconds ago.",
                        };
                    }

                    if (_definedLevel.indexOf(levelUser) === -1) {
                        return {
                            status: 401,
                            code: "x1f-S/S/securityLayer",
                            subcode: 0,
                            devDescription:
                                "The user's LEVEL does not appear in the LEVELS allowed by the API. User LEVEL: " + levelUser + ". User required: " + _definedLevel,
                        };
                    }

                    if (apiParams.required) {
                        for (const iterator of apiParams._definedParams) {
                            const item = apiParams.userParams.find((item) => item.nameBody === iterator);
                            if (item?.valueBody === null) {
                                return {
                                    status: 400,
                                    code: "x1f-S/S/securityLayer",
                                    subcode: 5,
                                    devDescription:
                                        "The PARAMETERS of the user call do not contain the PARAMETERS defined by the API.",
                                };
                            }
                        }
                    }

                    if (apiBody.required) {
                        for (const iterator of apiBody._definedBody) {
                            const item = apiBody.userBody.find((item) => item.nameBody === iterator);
                            if (item?.valueBody === null) {
                                return {
                                    status: 400,
                                    code: "x1f-S/S/securityLayer",
                                    subcode: 6,
                                    devDescription:
                                        "The BODY of the user call does not contain the BODY defined by the API.",
                                };
                            }
                        }
                    }

                    return {
                        status: 201,
                        code: "x19f-S/S/securityLayer",
                        subcode: 0,
                        devDescription:
                            "API has successfully passed all defined security guidelines.",
                    };
                }).catch(() => {
                    return {
                        status: 400,
                        code: "x1f-S/S/securityLayer",
                        subcode: 3,
                        devDescription:
                            "User TOKEN is invalid.",
                    };
                });
            }
        }
    }
}
