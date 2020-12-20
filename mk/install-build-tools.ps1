function Verify-Or-Delete-File {
    param (
        [Parameter(Mandatory)]
        [string]$File,
        [Parameter(Mandatory)]
        [string]$ExpectedDigest
    )
    $ActualDigest = ( Get-FileHash -Algorithm SHA256 $File ).Hash
    if ( $ActualDigest -eq $ExpectedDigest )
    {
        return
    }
    rm $File
    echo "Digest verification failed for $Url; actual $ActualDigest, expected $ExpectedDigest"
    exit 1
}

function Download-Zip-and-Extract-File {
    param (
        [Parameter(Mandatory)]
        [string]$Uri,
        [Parameter(Mandatory)]
        [string]$ZipExpectedDigest,
        [Parameter(Mandatory)]
        [string]$PathWithinZip,
        [Parameter(Mandatory)]
        [string]$FileExpectedDigest,
        [Parameter(Mandatory)]
        [string]$OutFile
    )
    $TmpZip = New-TemporaryFile
    Invoke-WebRequest -Uri $Uri -OutFile $TmpZip.FullName
    echo $TmpZip
    Verify-Or-Delete-File -File $TmpZip.FullName -ExpectedDigest $ZipExpectedDigest

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($TmpZip)
    $zip.Entries |
        Where-Object { $_.FullName -eq $PathWithinZip } |
        ForEach-Object {
            $TmpFile = New-TemporaryFile
            # extract the selected items from the ZIP archive
            # and copy them to the out folder
            $FileName = $_.Name
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, "$TmpFile", $true)
            Verify-Or-Delete-File -File $TmpFile -ExpectedDigest $FileExpectedDigest
            Move-Item -Force $TmpFile $OutFile
        }
    $zip.Dispose()
}

$tools_dir = "target/tools"
mkdir -Force $tools_dir

# This is the file BoringSSL refers to in
# https://boringssl.googlesource.com/boringssl/+/26f8297177ad8033cc39de84afe9c2000430a66d.
$nasm_version = "nasm-2.13.03"
$nasm_zip = "$nasm_version-win64.zip"
$nasm_zip_sha256 = "B3A1F896B53D07854884C2E0D6BE7DEFBA7EBD09B864BBB9E6D69ADA1C3E989F"
$nasm_exe = "nasm.exe"
$nasm_exe_sha256 = "D8A933BF5CC3597C56193135CB78B225AB225E1F611D2FDB51EF6E3F555B21E3"
Download-Zip-and-Extract-File `
    -Uri "https://www.nasm.us/pub/nasm/releasebuilds/2.13.03/win64/$nasm_zip" `
    -ZipExpectedDigest "$nasm_zip_sha256" `
    -PathWithinZip "$nasm_version/$nasm_exe" `
    -FileExpectedDigest "$nasm_exe_sha256" `
    -OutFile "$tools_dir/$nasm_exe"
