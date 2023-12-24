const { NotImplementedError } = require('../extensions/index.js');

/**
 * Implement class VigenereCipheringMachine that allows us to create
 * direct and reverse ciphering machines according to task description
 * 
 * @example
 * 
 * const directMachine = new VigenereCipheringMachine();
 * 
 * const reverseMachine = new VigenereCipheringMachine(false);
 * 
 * directMachine.encrypt('attack at dawn!', 'alphonse') => 'AEIHQX SX DLLU!'
 * 
 * directMachine.decrypt('AEIHQX SX DLLU!', 'alphonse') => 'ATTACK AT DAWN!'
 * 
 * reverseMachine.encrypt('attack at dawn!', 'alphonse') => '!ULLD XS XQHIEA'
 * 
 * reverseMachine.decrypt('AEIHQX SX DLLU!', 'alphonse') => '!NWAD TA KCATTA'
 * 
 */
class VigenereCipheringMachine {
  base = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

  constructor(reverse = true) {
    this.reverse = !reverse;
  }

  encrypt(message, key) {
    if (!message || !key) throw new Error('Incorrect arguments!');
    const keyCopy = key.toUpperCase().split('');
    const copy = message.toUpperCase().split('');
    const cyphered = [];

    let keyCounter = 0;

    copy.forEach((char) => {
      if (this.base.includes(char)) {
        let num = this.base.indexOf(char);
        let keyNum = this.base.indexOf(keyCopy[keyCounter]);
        let resChar = this.base[(num + keyNum) % this.base.length];

        keyCounter = keyCounter >= key.length - 1 ? 0 : keyCounter + 1;
        cyphered.push(resChar);
      } else {
        cyphered.push(char);
      }
    });

    return this.reverse ? cyphered.reverse().join('') : cyphered.join('');
  }

  decrypt(encodedMessage, key) {
    if (!encodedMessage || !key) throw new Error('Incorrect arguments!');
    const keyCopy = key.toUpperCase().split('');
    const copy = encodedMessage.toUpperCase().split('');
    const deCyphered = [];

    let keyCounter = 0;

    copy.forEach((char) => {
      if (this.base.includes(char)) {
        let num = this.base.indexOf(char);
        let keyNum = this.base.indexOf(keyCopy[keyCounter]);
        let resChar =
          this.base[
          num - keyNum < 0
            ? this.base.length + (num - keyNum)
            : (num - keyNum) % this.base.length
          ];

        keyCounter = keyCounter >= key.length - 1 ? 0 : keyCounter + 1;
        deCyphered.push(resChar);
      } else {
        deCyphered.push(char);
      }
    });

    return this.reverse ? deCyphered.reverse().join('') : deCyphered.join('');
  }
}

module.exports = {
  VigenereCipheringMachine,
};
