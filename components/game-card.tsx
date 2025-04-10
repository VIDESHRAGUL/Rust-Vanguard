"use client"

import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Shield, Zap } from "lucide-react"
import type { Game } from "@/lib/types"

interface GameCardProps {
  game: Game
  onSelect: () => void
}

export default function GameCard({ game, onSelect }: GameCardProps) {
  return (
    <Card className="overflow-hidden border-gray-700 bg-gray-800/50 hover:bg-gray-800/80 transition-colors">
      <div className="aspect-video w-full overflow-hidden">
        <img
          src={game.image || "/placeholder.svg"}
          alt={game.title}
          className="w-full h-full object-cover transition-transform hover:scale-105 duration-300"
        />
      </div>
      <CardHeader className="pb-2">
        <CardTitle>{game.title}</CardTitle>
        <CardDescription className="text-gray-400">{game.description}</CardDescription>
      </CardHeader>
      <CardContent className="pb-2">
        <div className="grid grid-cols-2 gap-2 text-xs">
          <div className="flex items-center gap-1 text-yellow-500">
            <Zap className="h-3 w-3" />
            <span>Cheat: {game.cheatType}</span>
          </div>
          <div className="flex items-center gap-1 text-green-500">
            <Shield className="h-3 w-3" />
            <span>Anti-Cheat: {game.antiCheatType}</span>
          </div>
        </div>
      </CardContent>
      <CardFooter>
        <Button onClick={onSelect} className="w-full bg-green-600 hover:bg-green-700">
          Launch Game
        </Button>
      </CardFooter>
    </Card>
  )
}

