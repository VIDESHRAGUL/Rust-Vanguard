"use client"

import { useEffect, useRef, useState } from "react"
import { Button } from "@/components/ui/button"

interface PongGameProps {
  isCheatActive: boolean
}

export default function PongGame({ isCheatActive }: PongGameProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [gameStarted, setGameStarted] = useState(false)
  const [playerScore, setPlayerScore] = useState(0)
  const [aiScore, setAiScore] = useState(0)
  const [gameOver, setGameOver] = useState(false)
  const [winner, setWinner] = useState<string>("")

  useEffect(() => {
    if (!gameStarted || !canvasRef.current) return

    const canvas = canvasRef.current
    const ctx = canvas.getContext("2d")
    if (!ctx) return

    // Game variables
    const paddleHeight = 80
    const paddleWidth = 10
    const ballSize = 10
    let ballX = canvas.width / 2
    let ballY = canvas.height / 2
    let ballSpeedX = 5
    let ballSpeedY = 2
    let playerPaddleY = (canvas.height - paddleHeight) / 2
    let aiPaddleY = (canvas.height - paddleHeight) / 2
    let upPressed = false
    let downPressed = false
    let playerScoreValue = 0
    let aiScoreValue = 0
    const winScore = 5

    // Time manipulation variables for cheat
    let lastFrameTime = Date.now()
    let gameSpeed = 1

    // Event listeners
    const keyDownHandler = (e: KeyboardEvent) => {
      if (e.key === "Up" || e.key === "ArrowUp") {
        upPressed = true
      } else if (e.key === "Down" || e.key === "ArrowDown") {
        downPressed = true
      }
    }

    const keyUpHandler = (e: KeyboardEvent) => {
      if (e.key === "Up" || e.key === "ArrowUp") {
        upPressed = false
      } else if (e.key === "Down" || e.key === "ArrowDown") {
        downPressed = false
      }
    }

    document.addEventListener("keydown", keyDownHandler)
    document.addEventListener("keyup", keyUpHandler)

    // Draw functions
    function drawBall() {
      ctx.beginPath()
      ctx.arc(ballX, ballY, ballSize, 0, Math.PI * 2)
      ctx.fillStyle = "#FFFFFF"
      ctx.fill()
      ctx.closePath()
    }

    function drawPaddles() {
      // Player paddle
      ctx.beginPath()
      ctx.rect(0, playerPaddleY, paddleWidth, paddleHeight)
      ctx.fillStyle = "#0095DD"
      ctx.fill()
      ctx.closePath()

      // AI paddle
      ctx.beginPath()
      ctx.rect(canvas.width - paddleWidth, aiPaddleY, paddleWidth, paddleHeight)
      ctx.fillStyle = isCheatActive ? "#FF5500" : "#0095DD"
      ctx.fill()
      ctx.closePath()
    }

    function drawScore() {
      ctx.font = "16px Arial"
      ctx.fillStyle = "#FFFFFF"
      ctx.textAlign = "left"
      ctx.fillText(`Player: ${playerScoreValue}`, 10, 20)
      ctx.textAlign = "right"
      ctx.fillText(`AI: ${aiScoreValue}`, canvas.width - 10, 20)
    }

    function drawNet() {
      ctx.beginPath()
      ctx.setLineDash([5, 15])
      ctx.moveTo(canvas.width / 2, 0)
      ctx.lineTo(canvas.width / 2, canvas.height)
      ctx.strokeStyle = "#FFFFFF"
      ctx.stroke()
      ctx.setLineDash([])
      ctx.closePath()
    }

    // AI paddle movement
    function moveAIPaddle() {
      const paddleCenter = aiPaddleY + paddleHeight / 2
      const ballCenterY = ballY

      // If cheat is active, AI becomes perfect
      if (isCheatActive) {
        // Perfect AI that always follows the ball
        aiPaddleY = ballY - paddleHeight / 2

        // Keep paddle within canvas bounds
        if (aiPaddleY < 0) {
          aiPaddleY = 0
        } else if (aiPaddleY + paddleHeight > canvas.height) {
          aiPaddleY = canvas.height - paddleHeight
        }
      } else {
        // Normal AI with some delay and imperfection
        const aiSpeed = 3
        if (paddleCenter < ballCenterY - 10) {
          aiPaddleY += aiSpeed
        } else if (paddleCenter > ballCenterY + 10) {
          aiPaddleY -= aiSpeed
        }

        // Keep paddle within canvas bounds
        if (aiPaddleY < 0) {
          aiPaddleY = 0
        } else if (aiPaddleY + paddleHeight > canvas.height) {
          aiPaddleY = canvas.height - paddleHeight
        }
      }
    }

    // Main game loop
    function draw() {
      // Calculate delta time for time-based movement
      const currentTime = Date.now()
      const deltaTime = (currentTime - lastFrameTime) / 16.67 // Normalize to ~60fps
      lastFrameTime = currentTime

      // Apply time manipulation cheat if active
      if (isCheatActive) {
        gameSpeed = 0.5 // Slow down the game for the player
      } else {
        gameSpeed = 1
      }

      // Clear canvas
      ctx.clearRect(0, 0, canvas.width, canvas.height)

      // Draw game elements
      drawNet()
      drawBall()
      drawPaddles()
      drawScore()

      // Move player paddle
      if (upPressed && playerPaddleY > 0) {
        playerPaddleY -= 7 * deltaTime * gameSpeed
      } else if (downPressed && playerPaddleY + paddleHeight < canvas.height) {
        playerPaddleY += 7 * deltaTime * gameSpeed
      }

      // Move AI paddle
      moveAIPaddle()

      // Move ball
      ballX += ballSpeedX * deltaTime * gameSpeed
      ballY += ballSpeedY * deltaTime * gameSpeed

      // Ball collision with top and bottom walls
      if (ballY - ballSize < 0 || ballY + ballSize > canvas.height) {
        ballSpeedY = -ballSpeedY
      }

      // Ball collision with paddles
      if (ballX - ballSize < paddleWidth && ballY > playerPaddleY && ballY < playerPaddleY + paddleHeight) {
        ballSpeedX = -ballSpeedX
        // Add some angle based on where the ball hits the paddle
        const hitPosition = (ballY - (playerPaddleY + paddleHeight / 2)) / (paddleHeight / 2)
        ballSpeedY = hitPosition * 5
      } else if (
        ballX + ballSize > canvas.width - paddleWidth &&
        ballY > aiPaddleY &&
        ballY < aiPaddleY + paddleHeight
      ) {
        ballSpeedX = -ballSpeedX
        // Add some angle based on where the ball hits the paddle
        const hitPosition = (ballY - (aiPaddleY + paddleHeight / 2)) / (paddleHeight / 2)
        ballSpeedY = hitPosition * 5
      }

      // Ball out of bounds - scoring
      if (ballX < 0) {
        // AI scores
        aiScoreValue++
        setAiScore(aiScoreValue)
        resetBall()
      } else if (ballX > canvas.width) {
        // Player scores
        playerScoreValue++
        setPlayerScore(playerScoreValue)
        resetBall()
      }

      // Check for game over
      if (playerScoreValue >= winScore) {
        setGameOver(true)
        setWinner("Player")
        setGameStarted(false)
        return
      } else if (aiScoreValue >= winScore) {
        setGameOver(true)
        setWinner("AI")
        setGameStarted(false)
        return
      }

      if (gameStarted) {
        requestAnimationFrame(draw)
      }
    }

    // Reset ball to center
    function resetBall() {
      ballX = canvas.width / 2
      ballY = canvas.height / 2
      ballSpeedX = -ballSpeedX
      ballSpeedY = Math.random() * 4 - 2
    }

    // Start the game loop
    lastFrameTime = Date.now()
    draw()

    return () => {
      document.removeEventListener("keydown", keyDownHandler)
      document.removeEventListener("keyup", keyUpHandler)
    }
  }, [gameStarted, isCheatActive])

  const startGame = () => {
    setGameStarted(true)
    setGameOver(false)
    setPlayerScore(0)
    setAiScore(0)
    setWinner("")
  }

  return (
    <div className="flex flex-col items-center justify-center h-full">
      <div className="mb-4 flex justify-between w-full max-w-md">
        <div className="text-blue-500">Player: {playerScore}</div>
        <div className="text-red-500">AI: {aiScore}</div>
      </div>

      <canvas ref={canvasRef} width={480} height={320} className="bg-gray-900 border border-gray-700 rounded-md" />

      {!gameStarted && (
        <div className="mt-4">
          <Button onClick={startGame} className="bg-green-600 hover:bg-green-700">
            {gameOver ? "Play Again" : "Start Game"}
          </Button>
          {gameOver && (
            <div className="mt-2 text-center">
              <p className={winner === "Player" ? "text-green-500" : "text-red-500"}>
                {winner === "Player" ? "You win!" : "AI wins!"}
              </p>
            </div>
          )}
        </div>
      )}

      {isCheatActive && gameStarted && (
        <div className="mt-4 text-yellow-500 text-sm">
          Time Manipulation Cheat Active: Game slowed down for player advantage
        </div>
      )}

      <div className="mt-4 text-sm text-gray-400">Use ↑ and ↓ arrow keys to move your paddle</div>
    </div>
  )
}

