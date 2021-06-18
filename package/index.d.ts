
/**
 * 加密
 * @param password 密码
 * @param text 待加密内容
 * @returns 加密后的密文 base64 格式
 */
export function encrypt(password: string, text: string): string;
/**
 * 解密
 * @param password 密码
 * @param text 加密内容 base64 格式
 */
export function decrypt(password: string, text: string): string;

/**
* 载入
*/
export function load(): Promise<void>;

