"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Shield, LogOut, Gamepad2, Zap, ShieldAlert, AlertTriangle } from "lucide-react"
import GameCard from "@/components/game-card"
import GameView from "@/components/game-view"
import type { Game } from "@/lib/types"

interface DashboardProps {
  onLogout: () => void
}

export default function Dashboard({ onLogout }: DashboardProps) {
  const [selectedGame, setSelectedGame] = useState<Game | null>(null)
  const [isAntiCheatRunning, setIsAntiCheatRunning] = useState(false)
  const [isCheatRunning, setIsCheatRunning] = useState(false)
  const [cheatDetected, setCheatDetected] = useState(false)
  const [rustLoaded, setRustLoaded] = useState(false)

  // Simulate loading Rust WASM module
  useEffect(() => {
    const loadRust = async () => {
      // In a real app, this would load the Rust WASM module
      await new Promise((resolve) => setTimeout(resolve, 1000))
      setRustLoaded(true)
      console.log("Rust anti-cheat core loaded")
    }

    loadRust()
  }, [])

  const games: Game[] = [
    {
      id: "memory-match",
      title: "Memory Match",
      description: "Match pairs of cards to win",
      image: "/images/memory-match.png",
      cheatType: "Buffer Overflow",
      antiCheatType: "Memory Integrity Verification",
    },
    {
      id: "minesweeper",
      title: "Minesweeper",
      description: "Find all mines without detonating any",
      image: "/images/minesweeper.png",
      cheatType: "Memory Injection",
      antiCheatType: "Process Monitoring",
    },
    {
      id: "number-guess",
      title: "Number Guessing",
      description: "Guess the correct number in fewest attempts",
      image: "/images/number-guess.png",
      cheatType: "API Manipulation",
      antiCheatType: "Request Validation",
    },
    {
      id: "space-shooter",
      title: "Space Shooter",
      description: "Destroy enemies and avoid collisions",
      image: "/images/space-shooter.png",
      cheatType: "Time Manipulation",
      antiCheatType: "Server-side Verification",
    },
    {
      id: "puzzle-slide",
      title: "Puzzle Slide",
      description: "Arrange tiles in the correct order",
      image: "/images/puzzle-slide.png",
      cheatType: "Code Injection",
      antiCheatType: "Code Integrity Checking",
    },
    {
      id: "tic-tac-toe",
      title: "Tic Tac Toe",
      description: "Classic X and O game",
      image: "/images/tic-tac-toe.png",
      cheatType: "Logic Manipulation",
      antiCheatType: "State Validation",
    },
  ]

  const handleGameSelect = (game: Game) => {
    setSelectedGame(game)
    setIsCheatRunning(false)
    setCheatDetected(false)
  }

  const handleBackToGames = () => {
    setSelectedGame(null)
    setIsCheatRunning(false)
    setCheatDetected(false)
  }

  const toggleAntiCheat = () => {
    setIsAntiCheatRunning(!isAntiCheatRunning)
    if (isCheatRunning && !isAntiCheatRunning) {
      setCheatDetected(true)
    }
  }

  const toggleCheat = () => {
    const newCheatState = !isCheatRunning
    setIsCheatRunning(newCheatState)

    if (newCheatState && isAntiCheatRunning) {
      // Anti-cheat detects the cheat
      setTimeout(() => {
        setCheatDetected(true)
      }, 1500)
    } else {
      setCheatDetected(false)
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 to-gray-800 text-white">
      <header className="border-b border-gray-700 bg-gray-800/80 backdrop-blur-sm">
        <div className="container mx-auto px-4 py-4 flex justify-between items-center">
          <div className="flex items-center gap-2">
            <Shield className="h-8 w-8 text-green-500" />
            <h1 className="text-2xl font-bold">Rust-Vanguard</h1>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-sm text-gray-400">
              Logged in as <span className="text-green-500 font-medium">frey</span>
            </div>
            <Button variant="ghost" size="sm" onClick={onLogout} className="text-gray-400 hover:text-white">
              <LogOut className="h-4 w-4 mr-2" />
              Logout
            </Button>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8">
        {selectedGame ? (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <div className="flex items-center gap-2">
                <Gamepad2 className="h-6 w-6 text-green-500" />
                <h2 className="text-2xl font-bold">{selectedGame.title}</h2>
              </div>
              <Button variant="outline" onClick={handleBackToGames}>
                Back to Games
              </Button>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="lg:col-span-2">
                <Card className="border-gray-700 bg-gray-800/50">
                  <CardHeader>
                    <CardTitle>Game Window</CardTitle>
                    <CardDescription className="text-gray-400">
                      {cheatDetected ? (
                        <div className="flex items-center text-red-500 gap-2">
                          <AlertTriangle className="h-4 w-4" />
                          Cheat detected! Game suspended by anti-cheat system.
                        </div>
                      ) : (
                        `${selectedGame.description}`
                      )}
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="min-h-[400px] flex items-center justify-center">
                    {cheatDetected ? (
                      <div className="text-center space-y-4">
                        <ShieldAlert className="h-16 w-16 text-red-500 mx-auto" />
                        <h3 className="text-xl font-bold text-red-500">Anti-Cheat Alert</h3>
                        <p className="max-w-md mx-auto text-gray-400">
                          The anti-cheat system has detected unauthorized modifications to the game. The game has been
                          suspended to maintain fair play.
                        </p>
                        <Button
                          variant="destructive"
                          onClick={() => {
                            setIsCheatRunning(false)
                            setCheatDetected(false)
                          }}
                        >
                          Disable Cheat to Continue
                        </Button>
                      </div>
                    ) : (
                      <GameView
                        game={selectedGame}
                        isCheatActive={isCheatRunning && !cheatDetected}
                        isAntiCheatActive={isAntiCheatRunning}
                      />
                    )}
                  </CardContent>
                </Card>
              </div>

              <div className="space-y-6">
                <Card className="border-gray-700 bg-gray-800/50">
                  <CardHeader>
                    <CardTitle>Game Controls</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="space-y-2">
                      <div className="flex justify-between items-center">
                        <div className="flex items-center gap-2">
                          <Shield className="h-5 w-5 text-green-500" />
                          <span>Anti-Cheat System</span>
                        </div>
                        <Button
                          variant={isAntiCheatRunning ? "default" : "outline"}
                          size="sm"
                          onClick={toggleAntiCheat}
                          className={isAntiCheatRunning ? "bg-green-600 hover:bg-green-700" : ""}
                          disabled={!rustLoaded}
                        >
                          {!rustLoaded ? "Loading..." : isAntiCheatRunning ? "Running" : "Disabled"}
                        </Button>
                      </div>
                      <p className="text-sm text-gray-400">
                        {selectedGame.antiCheatType}: Monitors and prevents unauthorized game modifications
                      </p>
                    </div>

                    <div className="space-y-2">
                      <div className="flex justify-between items-center">
                        <div className="flex items-center gap-2">
                          <Zap className="h-5 w-5 text-yellow-500" />
                          <span>Cheat System</span>
                        </div>
                        <Button
                          variant={isCheatRunning ? "default" : "outline"}
                          size="sm"
                          onClick={toggleCheat}
                          disabled={cheatDetected}
                          className={isCheatRunning ? "bg-yellow-600 hover:bg-yellow-700" : ""}
                        >
                          {isCheatRunning ? "Active" : "Inactive"}
                        </Button>
                      </div>
                      <p className="text-sm text-gray-400">
                        {selectedGame.cheatType}: Exploits game vulnerabilities for unfair advantage
                      </p>
                    </div>
                  </CardContent>
                </Card>

                <Card className="border-gray-700 bg-gray-800/50">
                  <CardHeader>
                    <CardTitle>Vulnerability Information</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <Tabs defaultValue="cheat">
                      <TabsList className="grid w-full grid-cols-2 bg-gray-700">
                        <TabsTrigger value="cheat">Cheat System</TabsTrigger>
                        <TabsTrigger value="anticheat">Anti-Cheat</TabsTrigger>
                      </TabsList>
                      <TabsContent value="cheat" className="space-y-4 mt-4">
                        <h3 className="font-bold text-yellow-500">{selectedGame.cheatType}</h3>
                        <p className="text-sm text-gray-400">
                          This cheat exploits a {selectedGame.cheatType.toLowerCase()} vulnerability in the game,
                          allowing the player to gain unfair advantages by manipulating game memory or logic.
                        </p>
                        <div className="text-xs text-gray-500 border-t border-gray-700 pt-2 mt-2">
                          <p>For educational purposes only. Demonstrates security vulnerabilities.</p>
                        </div>
                      </TabsContent>
                      <TabsContent value="anticheat" className="space-y-4 mt-4">
                        <h3 className="font-bold text-green-500">{selectedGame.antiCheatType}</h3>
                        <p className="text-sm text-gray-400">
                          This anti-cheat system uses {selectedGame.antiCheatType.toLowerCase()} techniques to detect
                          and prevent cheating attempts, ensuring fair gameplay.
                        </p>
                        <div className="text-xs text-gray-500 border-t border-gray-700 pt-2 mt-2">
                          <p>Demonstrates security protection mechanisms in gaming environments.</p>
                        </div>
                      </TabsContent>
                    </Tabs>
                  </CardContent>
                </Card>
              </div>
            </div>
          </div>
        ) : (
          <div className="space-y-8">
            <div>
              <h2 className="text-2xl font-bold mb-2 flex items-center gap-2">
                <Gamepad2 className="h-6 w-6 text-green-500" />
                Game Library
              </h2>
              <p className="text-gray-400">
                Select a game to play and explore its security vulnerabilities and protections
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {games.map((game) => (
                <GameCard key={game.id} game={game} onSelect={() => handleGameSelect(game)} />
              ))}
            </div>
          </div>
        )}
      </main>

      <footer className="border-t border-gray-700 py-4 mt-8">
        <div className="container mx-auto px-4 text-center text-gray-500 text-sm">
          <p>Rust-Vanguard - Game Security Demonstration Platform</p>
          <p className="mt-1">For educational purposes only</p>
        </div>
      </footer>
    </div>
  )
}

