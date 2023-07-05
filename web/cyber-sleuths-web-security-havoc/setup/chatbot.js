const { response } = require('express');
const fs = require('fs');
const path = require('path');

const bot = require('./bot')


function genfilename(){
  const characters = 'abcdefghijklmnopqrstuvwxyz';
  let filename = '';

  for (let i = 0; i < 6; i++) {
    const randomIndex = Math.floor(Math.random() * characters.length);
    filename += characters[randomIndex];
  }

  return filename + ".html";
}


module.exports = (message, user_id) => {
    const botName = 'Bot';
  
    // Define chatbot rules and responses
    const rules = [
      { pattern: /^upload\s(.*)$/i,response: "", protected: true },
      { pattern: /^upload/i, response: `USAGE: upload [file_contents]`,  protected: true },
      { pattern: /flag/i, response: 'Oh hey admin! Here is your flag: CCSC{... System malfunction, flag command has been removed due to security issues', protected: true },
      { pattern: /hello/i, response: 'Hello there', protected: false },
      { pattern: /hey/i, response: 'Heyyyyyyy ;)', protected: false },
      { pattern: /hi/i, response: 'Hi :D', protected: false },
      { pattern: /bye/i, response: 'ciao :)', protected: false },
      { pattern: /parperis/i, response: 'Yes Parperis is my creator! :D', protected: false },
      { pattern: /(help|\?)/i, response: 
                                    `| Command | Description                       |
| ------- | --------------------------------- |
| help    | This help page                    |
| flag    | Print flag                        |
| upload  | Upload file contents to file      |`, protected: true },
      { pattern: /^(https?:\/\/)([\w-]+\.[\w.-]+)|(https?:\/\/)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d{1,5})?(\/\S*)?$/, response: 'Hmm, that looks interesting, ill visit it now!', protected: false },
    ];
  
    // Check each rule against the user's message and generate a response
    for (const rule of rules) {

      if (rule.pattern.test(message)) {

        bot_response =  {
          username: botName,
          message: rule.response
        }


        // If admin command and user is admin
        if(rule.protected){
          
          if(user_id == 1){

            // Upload command
            if(rule == rules[0]){
              matches = message.match(rule.pattern);

              filename = genfilename();
              contents = matches[1];

              filepath = path.join("uploads", filename)
  
              fs.writeFile(filepath, contents, 'utf8', (err) => { console.log(err)});
  
              console.log(filepath)
              
              rule.response = `Uploaded file successfully - Visit at /tmp-${filename}`

              bot_response =  {
                username: botName,
                message: rule.response
              }
            }

          }else{
            bot_response = {
              username: botName,
              message: "Only the admin can send this message"
            }
          }
          
        }
        

        // If website is detected, get bot to visit it
        if(rule == rules[rules.length -1]){ 
          bot.goto(message)
        }


        return bot_response

      }
    }
  
    // If no matching rule found, provide a default response
    return {
      username: botName,
      message: `I'm sorry, I didn't understand that.`,
    };
  };