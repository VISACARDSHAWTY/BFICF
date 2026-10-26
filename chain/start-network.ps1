$nodes = @('oem', 'cloud', 'edge', 'user', 'secauth')
$baseDir = "C:\Users\MARC\Desktop\ts project\bficf\chain"

foreach ($node in $nodes) {
    $dataPath = "$baseDir\data\$node"
    $genesisPath = "$baseDir\networkFiles\genesis.json"
    $keyPath = "$baseDir\nodes\$node\key"

    $i = [array]::IndexOf($nodes, $node)
    $p2pPort = 30303 + $i
    $rpcPort = 8545 + $i
    $metricsPort = 9545 + $i

    $cmd = "C:\Besu\besu-26.10.0\bin\besu.bat --data-path=`"$dataPath`" --genesis-file=`"$genesisPath`" --node-private-key-file=`"$keyPath`" --p2p-port=$p2pPort --rpc-http-enabled --rpc-http-port=$rpcPort --rpc-http-api=ETH,NET,QBFT,WEB3,ADMIN,TXPOOL --host-allowlist=* --min-gas-price=0 --metrics-enabled --metrics-port=$metricsPort --sync-mode=FULL"

    Start-Process -FilePath "cmd.exe" -ArgumentList "/k $cmd"
}