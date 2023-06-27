// Flag is hidden in the function.js file.
const temp1 = String.fromCharCode(0x45);
const temp2 = String.fromCharCode(0x43);
const temp3 = String.fromCharCode(0x53);

const { v1, v2, v3, v4, v5, space, v6, v7, v8, v9, v10, v11,  } = {
    v1: String.fromCharCode(0x48), v2: String.fromCharCode(0x69), v3: String.fromCharCode(0x64), v4: String.fromCharCode(0x65),
    v5: String.fromCharCode(0x6E), space: String.fromCharCode(0x5F), v6: String.fromCharCode(0x53), v7: String.fromCharCode(0x69),
    v8: String.fromCharCode(0x67), v9: String.fromCharCode(0x6E), v10: String.fromCharCode(0x6C), v11: String.fromCharCode(0x73)
};


const var1 = `${v1}${v2}${v3}${v3}${v4}${v5}${space}${v6}${v7}${v8}${v9}a${v10}${v11}${space}`;


const {v12, v13, v14, v15, v16, v17 } ={
    v12: String.fromCharCode(0x44), v13: String.fromCharCode(0x33), v14: String.fromCharCode(0x74),
    v15: String.fromCharCode(0x63), v16: String.fromCharCode(0x74), v17: String.fromCharCode(0x64)
};

const var2 = `${v12}${v13}${v14}e${v15}${v16}${v13}${v17}`;

let text = `${temp2}${temp2}${temp3}${temp2}{${var1}${var2}}`;
console.log(text)