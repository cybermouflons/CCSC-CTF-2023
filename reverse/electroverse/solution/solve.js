// Flag is hidden in the function.js file.
const temp1 = String.fromCharCode(0x45);
const temp2 = String.fromCharCode(0x43);
const temp3 = String.fromCharCode(0x53);

const { H1, i1, d1, e1, n1, hiddenSpace, S1, i2, g1, n2, l1, s1, hiddenSpace2, D1, _3, t1, c1, t2, _3_2, d2 } = {
    H1: String.fromCharCode(0x48), i1: String.fromCharCode(0x69), d1: String.fromCharCode(0x64), e1: String.fromCharCode(0x65),
    n1: String.fromCharCode(0x6E), hiddenSpace: String.fromCharCode(0x5F), S1: String.fromCharCode(0x53), i2: String.fromCharCode(0x69),
    g1: String.fromCharCode(0x67), n2: String.fromCharCode(0x6E), l1: String.fromCharCode(0x6C), s1: String.fromCharCode(0x73),
    hiddenSpace2: String.fromCharCode(0x5F), D1: String.fromCharCode(0x44), _3: String.fromCharCode(0x33), t1: String.fromCharCode(0x74),
    c1: String.fromCharCode(0x63), t2: String.fromCharCode(0x74), _3_2: String.fromCharCode(0x33), d2: String.fromCharCode(0x64)
    };
    
const hiddenPart = `${H1}${i1}${d1}${e1}${n1}${hiddenSpace}${S1}${i2}${g1}${n2}${l1}${s1}${hiddenSpace2}${D1}${_3}${t1}${c1}${t2}${_3_2}${d2}`;

let text = `${temp2}${temp2}${temp3}${temp2}${String.fromCharCode(0x32)}0${String.fromCharCode(0x32)}3{${hiddenPart}}`;
    console.log(text)