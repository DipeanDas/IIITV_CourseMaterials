function [u] = myUtilitiesTwoPlayerGame1(studentID)

% studentID = 202151188
% Enter your student ID
% Usage:
% u = myUtilitiesTwoPlayerGame1(202151188)

seed = 100 + mod(studentID, 10);

rand("seed",seed);
u = round(20*rand(1,16));

end

function [u] = myUtilitiesTwoPlayerGame1(studentID)
    % studentID = 202151188
    % Enter your student ID
    % Usage:
    % u = myUtilitiesTwoPlayerGame1(202151188)

    seed = 100 + mod(studentID, 10);

    rand("seed", seed);
    u = round(20 * rand(1, 16));
end

function result = twoPlayerGame(player1Move, player2Move, studentID)
    % Generate utilities for both players using the provided utility function
    utilities = myUtilitiesTwoPlayerGame1(studentID);
    
    % Ensure valid moves
    if player1Move < 1 || player1Move > 16 || player2Move < 1 || player2Move > 16
        error('Invalid moves. Moves should be integers between 1 and 16.');
    end
    
    % Determine the payoff for each player based on their moves and utilities
    payoffPlayer1 = utilities(player1Move);
    payoffPlayer2 = utilities(player2Move);
    
    % Determine the result of the game
    if payoffPlayer1 > payoffPlayer2
        result = 'Player 1 wins!';
    elseif payoffPlayer1 < payoffPlayer2
        result = 'Player 2 wins!';
    else
        result = 'It''s a tie!';
    end
    
    % Display the result
    disp(result);
end

