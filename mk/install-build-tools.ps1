function Download-File {
    param (
        [Parameter(Mandatory)]
        [string]$Url,
        [Parameter(Mandatory)]
        [string]$ExpectedDigest,
        [Parameter(Mandatory)]
        [string]$OutFile
    )
    $TmpFile = New-TemporaryFile
    Invoke-WebRequest -Uri $Url -OutFile $TmpFile.FullName
    $ActualDigest = ( Get-FileHash -Algorithm SHA256 $TmpFile ).Hash
    if ( $ActualDigest -eq $ExpectedDigest )
    {
        Move-Item -Force $TmpFile $OutFile
        return
    }

    echo "Digest verification failed for $Url; actual $ActualDigest, expected $ExpectedDigest"
    rm $TmpFile
    exit 1
}

$tools_dir = "target/tools"
mkdir -Force $tools_dir

Download-File `
    -Url 'https://www.tortall.net/projects/yasm/releases/yasm-1.3.0-win64.exe' `
    -ExpectedDigest D160B1D97266F3F28A71B4420A0AD2CD088A7977C2DD3B25AF155652D8D8D91F `
    -OutFile $tools_dir/yasm.exe
