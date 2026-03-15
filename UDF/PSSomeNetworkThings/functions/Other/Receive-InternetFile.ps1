function Receive-InternetFile {
    <#
    .SYNOPSIS
        Downloads a file from the internet with progress indication

    .DESCRIPTION
        Downloads a file using HttpWebRequest with a progress bar showing
        download status. Supports configurable buffer size and timeout.

    .PARAMETER url
        The URL to download from.

    .PARAMETER targetFile
        The local file path to save to.

    .PARAMETER BufferSize
        Download buffer size in bytes (default: 1000KB).

    .PARAMETER Timeout
        Request timeout in milliseconds (default: 15000).

    .EXAMPLE
        Receive-InternetFile "https://example.com/file.zip" "C:\Downloads\file.zip"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>

    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$url,
        [Parameter(Mandatory, Position = 1)]
        [string]$targetFile,
        [int]$BufferSize = 1000KB,
        [int]$Timeout = 15000 #15 second timeout
    )
    $uri = New-Object "System.Uri" "$url"
    $request = [System.Net.HttpWebRequest]::Create($uri)
    $request.set_Timeout($Timeout)
    $response = $request.GetResponse()
    $totalLength = [System.Math]::Floor($response.get_ContentLength()/1024)
    $responseStream = $response.GetResponseStream()
    $targetStream = New-Object -TypeName System.IO.FileStream -ArgumentList $targetFile, Create
    $buffer = new-object byte[] $BufferSize
    $count = $responseStream.Read($buffer,0,$buffer.length)
    $downloadedBytes = $count
    while ($count -gt 0) {
        $targetStream.Write($buffer, 0, $count)
        $count = $responseStream.Read($buffer,0,$buffer.length)
        $downloadedBytes = $downloadedBytes + $count
        Write-Progress -activity "Downloading file '$($url.split('/') | Select-Object -Last 1)'" `
                       -status "Downloaded ($([System.Math]::Floor($downloadedBytes/1024))K of $($totalLength)K): " `
                       -PercentComplete ((([System.Math]::Floor($downloadedBytes/1024)) / $totalLength)  * 100)
    }
    Write-Progress -activity "Finished downloading file '$($url.split('/') | Select-Object -Last 1)'"
    $targetStream.Flush()
    $targetStream.Close()
    $targetStream.Dispose()
    $responseStream.Dispose()
}