"use client"

import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { Shield } from "lucide-react"

interface RockPaperScissorsGameProps {
  isCheatActive: boolean
}

export default function RockPaperScissorsGame({ isCheatActive }: RockPaperScissorsGameProps) {
  const [playerChoice, setPlayerChoice] = useState<string | null>(null)
  const [computerChoice, setComputerChoice] = useState<string | null>(null)
  const [result, setResult] = useState<string | null>(null)
  const [playerScore, setPlayerScore] = useState(0)
  const [computerScore, setComputerScore] = useState(0)
  const [gameStarted, setGameStarted] = useState(false)
  const [roundInProgress, setRoundInProgress] = useState(false)
  const [cheatDetected, setCheatDetected] = useState(false)
  const [computerChoiceReady, setComputerChoiceReady] = useState(false)

  const choices = ["rock", "paper", "scissors"]

  // Start the game
  const startGame = () => {
    setPlayerScore(0)
    setComputerScore(0)
    setPlayerChoice(null)
    setComputerChoice(null)
    setResult(null)
    setGameStarted(true)
    setRoundInProgress(false)
    setCheatDetected(false)
    setComputerChoiceReady(false)
  }

  // Handle player choice
  const makeChoice = (choice: string) => {
    if (roundInProgress || cheatDetected) return

    setRoundInProgress(true)
    setPlayerChoice(choice)

    // In normal gameplay, computer makes choice at the same time
    if (!isCheatActive) {
      const aiChoice = choices[Math.floor(Math.random() * choices.length)]
      setComputerChoice(aiChoice)
      setComputerChoiceReady(true)
    } else {
      // With cheat active, computer choice is pre-determined but hidden
      // The cheat will try to delay the player's final choice to see computer's move
      const aiChoice = choices[Math.floor(Math.random() * choices.length)]
      setComputerChoice(aiChoice)

      // Check if anti-cheat is active
      const antiCheatActive = document.querySelector('[data-anticheat="active"]') !== null

      if (antiCheatActive) {
        // Anti-cheat detected the time manipulation attempt
        setCheatDetected(true)
      } else {
        // Reveal computer's choice before finalizing player's choice
        setComputerChoiceReady(true)
      }
    }
  }

  // Determine winner when both choices are made
  useEffect(() => {
    if (playerChoice && computerChoice && computerChoiceReady && !cheatDetected) {
      // Determine winner
      let roundResult: string

      if (playerChoice === computerChoice) {
        roundResult = "It's a tie!"
      } else if (
        (playerChoice === "rock" && computerChoice === "scissors") ||
        (playerChoice === "paper" && computerChoice === "rock") ||
        (playerChoice === "scissors" && computerChoice === "paper")
      ) {
        roundResult = "You win!"
        setPlayerScore((prev) => prev + 1)
      } else {
        roundResult = "Computer wins!"
        setComputerScore((prev) => prev + 1)
      }

      setResult(roundResult)

      // Reset for next round
      setTimeout(() => {
        setPlayerChoice(null)
        setComputerChoice(null)
        setResult(null)
        setRoundInProgress(false)
        setComputerChoiceReady(false)
      }, 2000)
    }
  }, [playerChoice, computerChoice, computerChoiceReady, cheatDetected])

  // Get icon for choice
  const getChoiceIcon = (choice: string | null) => {
    if (!choice) return "❓"

    switch (choice) {
      case "rock":
        return "👊"
      case "paper":
        return "✋"
      case "scissors":
        return "✌️"
      default:
        return "❓"
    }
  }

  return (
    <div className="flex flex-col items-center justify-center h-full">
      <div className="mb-4 flex justify-between w-full max-w-md">
        <div className="text-green-500">You: {playerScore}</div>
        <div className="text-red-500">Computer: {computerScore}</div>
      </div>

      {cheatDetected ? (
        <div className="text-center space-y-4">
          <Shield className="h-16 w-16 text-red-500 mx-auto" />
          <h3 className="text-xl font-bold text-red-500">Time Manipulation Detected!</h3>
          <p className="max-w-md mx-auto text-gray-400">
            The anti-cheat system has detected an attempt to manipulate game timing. This type of cheat tries to delay
            your move until after seeing the computer's choice.
          </p>
          <Button variant="destructive" onClick={startGame}>
            Restart Game
          </Button>
        </div>
      ) : gameStarted ? (
        <div className="flex flex-col items-center space-y-8">
          <div className="flex justify-around w-full">
            <div className="text-center">
              <div className="text-5xl mb-2">{getChoiceIcon(playerChoice)}</div>
              <div className="text-sm text-gray-400">Your Choice</div>
            </div>

            <div className="text-center">
              <div className="text-5xl mb-2">{computerChoiceReady ? getChoiceIcon(computerChoice) : "❓"}</div>
              <div className="text-sm text-gray-400">Computer's Choice</div>
            </div>
          </div>

          {result && (
            <div
              className={`text-xl font-bold ${
                result.includes("You win")
                  ? "text-green-500"
                  : result.includes("Computer wins")
                    ? "text-red-500"
                    : "text-yellow-500"
              }`}
            >
              {result}
            </div>
          )}

          <div className="flex space-x-4">
            {choices.map((choice) => (
              <Button
                key={choice}
                onClick={() => makeChoice(choice)}
                disabled={roundInProgress}
                className="bg-gray-700 hover:bg-gray-600 h-16 w-16 text-2xl"
              >
                {getChoiceIcon(choice)}
              </Button>
            ))}
          </div>
        </div>
      ) : (
        <Button onClick={startGame} className="bg-green-600 hover:bg-green-700">
          Start Game
        </Button>
      )}

      {isCheatActive && gameStarted && !cheatDetected && (
        <div className="mt-4 text-yellow-500 text-sm">
          Time Manipulation Cheat Active: Delaying player choice to see computer's move first
        </div>
      )}

      <div className="mt-6 bg-gray-800 p-4 rounded-md max-w-md">
        <h3 className="font-bold text-lg mb-2">How This Cheat Works:</h3>
        <p className="text-sm text-gray-300 mb-3">
          The Time Manipulation cheat exploits timing vulnerabilities to see the computer's choice before finalizing the
          player's move. It delays sending the player's choice to the server until after receiving the computer's
          choice.
        </p>

        <h3 className="font-bold text-lg mb-2">How Anti-Cheat Blocks It:</h3>
        <p className="text-sm text-gray-300">
          The anti-cheat system enforces strict timing requirements for all game actions. It monitors the sequence and
          timing of events, detecting when a player's move is suspiciously delayed or when the normal game flow is
          disrupted.
        </p>
      </div>
    </div>
  )
}

