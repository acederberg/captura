// NOTE: REPLACE ``code_salt`` as it is the thing that prevents arbitrary 
//       access to the ``POST /users`` endpoint.
const code_salt = "123456789abcdefghijklmnopqrstuvwxyz"
const axios = require("axios")

/* Registration script.
 *
 * @param {Event} event - Details about registration event.
 * @param {PreUserRegistrationAPI} api
 */
exports.onExecutePreUserRegistration = async (event, api) => {

  if (event.request.geoip.continentCode !== "NA") {
    const LOCALIZED_MESSAGES = {
      en: 'You are not allowed to register.',
      es: 'No tienes permitido registrarte.',
    };

    const userMessage = LOCALIZED_MESSAGES[event.request.language] || LOCALIZED_MESSAGES['en'];
    api.access.deny('no_signups_outside_north_america', userMessage);
  }

  await axios.post(
    "https://captura.foo/users",
    {
      code: event,
      email: event.user.email,
    }
  )
};
