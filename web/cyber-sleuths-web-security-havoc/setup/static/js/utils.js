$(document).ready(function() {

    // Function to send a message
    function sendMessage() {
        const message = messageInput.val().trim();
        if (message !== '') {
            addMessage('You', message);
            socket.send(message); 
            messageInput.val('');
        }
    }

    // Function to add a message to the message area
    function addMessage(username, message) {
        const messageElement = $('<div></div>').addClass('message').html(`<strong>${escapeHtml(username)}:</strong> ${escapeHtml(message)}`);
        messageArea.append(messageElement);

        // Scroll to the bottom of the message area
        messageArea.scrollTop(messageArea.prop('scrollHeight'));
    }

    host = window.location.host
    var socket = new WebSocket(`wss://${host}/chat`);

    const messageArea = $('#messageArea');
    const messageInput = $('#messageInput');

    socket.onmessage = (event) => {
        var response = JSON.parse(event.data);
        addMessage(response.username, response.message);
    };

    // Event listener for Enter key press in the message input
    messageInput.on('keydown', function(event) {
        if (event.key === 'Enter') {
            event.preventDefault();
            sendMessage();
        }
    });

});

function escapeHtml(text) {
    return $('<div>').text(text).html();
}

