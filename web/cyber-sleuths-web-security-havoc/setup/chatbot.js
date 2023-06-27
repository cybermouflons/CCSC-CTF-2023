const bot = require('./bot')
module.exports = (message, user_id) => {
    const botName = 'ChatBot';
  
    // Define chatbot rules and responses
    const rules = [
      { pattern: /hello/i, response: 'Hello, how can I assist you?' },
      { pattern: /hi/i, response: 'Hello, how can I assist you?' },
      { pattern: /bye/i, response: 'Goodbye! Have a nice day.' },
      { pattern: /flag/i, response: 'Only the admin can send this message' },
      { pattern: /help/i, response: 'Try harder' },
      { pattern: /parperis/i, response: 'Yes Parperis is my creator! :D' },
      { pattern: /^(https?:\/\/)([\w-]+\.[\w.-]+)|(https?:\/\/)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d{1,5})?(\/\S*)?$/, response: 'Hmm, that looks interesting, ill visit it now!' },
    ];
  
    // Check each rule against the user's message and generate a response
    for (const rule of rules) {
      if (rule.pattern.test(message)) {

        if(rule.pattern == rules[rules.length -1].pattern){ // If website is detected, get bot to visit it
          bot.goto(message);
        }

        if(rule.pattern == rules[3].pattern && user_id == 1){ // If website is detected, get bot to visit it
          return {
            username: botName,
            message: process.env.flag,
          };
        }

        return {
          username: botName,
          message: rule.response,
        };
      }
    }
  
    // If no matching rule found, provide a default response
    return {
      username: botName,
      message: `I'm sorry, I didn't understand that.`,
    };
  };