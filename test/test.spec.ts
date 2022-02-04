import tape from 'tape'
import { mnemonic, generateKey } from '../src'

tape('verify this crap works', (t) => {
    const m = mnemonic()
    console.log(m)
    t.pass('it generated something')

    const keypair = generateKey(m)
    console.log(keypair)
    t.pass('it generated a key, maybe?')
    t.end()
})