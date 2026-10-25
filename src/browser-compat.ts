/** crypto.randomUUID is absent on LAN HTTP even when getRandomValues is available. */
export const RANDOM_UUID_POLYFILL = `(()=>{
  if(typeof globalThis.crypto?.randomUUID==='function')return;
  if(typeof globalThis.crypto?.getRandomValues!=='function')return;
  Object.defineProperty(globalThis.crypto,'randomUUID',{configurable:true,value:()=>{
    const bytes=crypto.getRandomValues(new Uint8Array(16));bytes[6]=(bytes[6]&15)|64;bytes[8]=(bytes[8]&63)|128;
    const hex=Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
    return hex.slice(0,8)+'-'+hex.slice(8,12)+'-'+hex.slice(12,16)+'-'+hex.slice(16,20)+'-'+hex.slice(20);
  }});
})()`
