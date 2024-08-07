<?php

/*
 *
 *  ____           _            __           _____
 * |  _ \    ___  (_)  _ __    / _|  _   _  |_   _|   ___    __ _   _ __ ___
 * | |_) |  / _ \ | | | '_ \  | |_  | | | |   | |    / _ \  / _` | | '_ ` _ \
 * |  _ <  |  __/ | | | | | | |  _| | |_| |   | |   |  __/ | (_| | | | | | | |
 * |_| \_\  \___| |_| |_| |_| |_|    \__, |   |_|    \___|  \__,_| |_| |_| |_|
 *                                   |___/
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Zuri attempts to enforce "vanilla Minecraft" mechanics, as well as preventing
 * players from abusing weaknesses in Minecraft or its protocol, making your server
 * more safe. Organized in different sections, various checks are performed to test
 * players doing, covering a wide range including flying and speeding, fighting
 * hacks, fast block breaking and nukers, inventory hacks, chat spam and other types
 * of malicious behaviour.
 *
 * @author ReinfyTeam
 * @link https://github.com/ReinfyTeam/
 *
 *
 */

declare(strict_types=1);

namespace ReinfyTeam\Zuri\checks\network;

use pocketmine\event\Event;
use pocketmine\event\player\PlayerPreLoginEvent;
use pocketmine\scheduler\AsyncTask;
use pocketmine\Server;
use pocketmine\utils\Internet;
use ReinfyTeam\Zuri\checks\Check;
use function json_decode;

class ProxyBot extends Check {
	public function getName() : string {
		return "ProxyBot";
	}

	public function getSubType() : string {
		return "A";
	}

	public function maxViolations() : int {
		return 0;
	}

	public function checkJustEvent(Event $event) : void {
		if ($event instanceof PlayerPreLoginEvent) {
			$that = $this;
			Server::getInstance()->getAsyncPool()->submitTask(new class(fn($is) => $this->onQueryFinished($is, $event), $event->getIp()) extends AsyncTask {
				public function __construct(\Closure $callback, private string $ip) {
					$this->storeLocal('callback', $callback);
				}

				public function onRun() : void {
					$request = Internet::getUrl("https://proxycheck.io/v2/" . $this->ip, 10, ["Content-Type: application/json"]);
					$this->setResult(false);
					if ($request !== null) {
						$data = json_decode($request->getBody(), true, 16, JSON_PARTIAL_OUTPUT_ON_ERROR);

						if (($data["status"] ?? null) !== "error" && isset($data[$this->ip])) {
							$this->setResult($data[$this->ip]["proxy"] ?? null) === "yes";
						}
					}
				}

				public function onCompletion() : void {
					$this->fetchLocal('callback')($this->getResult());
				}
			});
		}
	}

	private function onQueryFinished(bool $proxy, PlayerPreLoginEvent $event) : void {
		$this->warn($event->getPlayerInfo()->getUsername());
		$session = $event->getSession();
		if (!$session->isConnected()) {
			return;
		}
		if ($proxy) {
			$session->disconnect(self::getData(self::ANTIBOT_MESSAGE));
		}
	}
}