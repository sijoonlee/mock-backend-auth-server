import bcrypt from 'bcrypt';

/**
 * 
 * @param {string} password 
 * @returns Promise<string>
 */
 async function encryptPassword(password) {
    return bcrypt.hash(password, await bcrypt.genSalt(10))
}

/**
 * 
 * @param {string} password 
 * @param {string} encryptedPassword 
 * @returns Promise<boolean>
 */
function comparePassword(password, encryptedPassword) {
    return bcrypt.compare(password, encryptedPassword)
}

export {
    encryptPassword,
    comparePassword
}
