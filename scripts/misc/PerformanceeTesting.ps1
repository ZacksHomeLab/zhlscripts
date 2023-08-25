$a1 = [System.Collections.Generic.List[Object]]::new()
$a2 = [System.Collections.Generic.List[Object]]::new()
$a3 = [System.Collections.Generic.List[Object]]::new()
$a4 = [System.Collections.Generic.List[Object]]::new()
$a5 = [System.Collections.Generic.List[Object]]::new()
$a6 = [System.Collections.Generic.List[Object]]::new()

$Seed = 1000
1..100 | ForEach-Object {
    $null = $a1.Add($(Measure-Command {
    
    $ListDotAdd = [System.Collections.Generic.List[Int]]::new()
        1..10000 | ForEach-Object {
            $ListDotAdd.Add((Get-Random -SetSeed $Seed -Minimum 1 -Maximum 10000))
        }
        Remove-Variable -Name ListDotAdd
    }).TotalSeconds)

    $null = $a2.Add($(Measure-Command {

        $ListForEach = [System.Collections.Generic.List[Int]]::new()
        $ListForEach = foreach ($Number in 1..10000) {
                Get-Random -SetSeed $Seed -Minimum 1 -Maximum 10000
            }
            Remove-Variable -Name ListForEach
        }).TotalSeconds)

    $null = $a3.Add($(Measure-Command {

        $ListAddRange = [System.Collections.Generic.List[Int]]::new()
        $ListAddRange.AddRange([int[]](1..10000))

        $ListAddRange = foreach ($i in 1..10000) {
            Get-Random -SetSeed $Seed -Minimum 1 -Maximum 10000
        }
        Remove-Variable -Name ListAddRange
    }).TotalSeconds)

    $null = $a4.Add($(Measure-Command {

        $ArrayPreAllocForEach = [int[]]::new(10000)

        $ArrayPreAllocForEach = foreach ($i in 1..10000) {
            Get-Random -SetSeed $Seed -Minimum 1 -Maximum 10000
        }
        Remove-Variable -Name ArrayPreAllocForEach
    }).TotalSeconds)

    $null = $a5.Add($(Measure-Command {

        $ArrayForEach = @()

        $ArrayForEach = foreach ($i2 in 1..10000) {
            $ArrayForEach += (Get-Random -SetSeed $Seed -Minimum 1 -Maximum 10000)
        }
        Remove-Variable -Name ArrayForEach
    }).TotalSeconds)

    $null = $a6.Add($(Measure-Command {

        $ArrayForEachNoAdd = @()

        $ArrayForEachNoAdd = foreach ($num in 1..10000) {
            Get-Random -SetSeed $Seed -Minimum 1 -Maximum 10000
        }
        Remove-Variable -Name ArrayForEachNoAdd
    }).TotalSeconds)
}

@"
Method, Time
ListDotAdd,            $($a1 | Measure-Object -Sum | ForEach-Object {$_.sum.tostring('000.00000')})
ListForEach,           $($a2 | Measure-Object -Sum | ForEach-Object {$_.sum.tostring('000.00000')})
ListAddRange,          $($a3 | Measure-Object -Sum | ForEach-Object {$_.sum.tostring('000.00000')})
ArrayPreAllocForEach,  $($a4 | Measure-Object -Sum | ForEach-Object {$_.sum.tostring('000.00000')})
ArrayForEach,          $($a5 | Measure-Object -Sum | ForEach-Object {$_.sum.tostring('000.00000')})
ArrayForEachNoAdd,     $($a6 | Measure-Object -Sum | ForEach-Object {$_.sum.tostring('000.00000')})
"@ | ConvertFrom-Csv | Sort-Object time | Format-Table -AutoSize

<#
Method               Time
------               ----
ListForEach          009.04267
ArrayForEachNoAdd    009.04949
ArrayPreAllocForEach 009.06247
ListAddRange         009.10966
ListDotAdd           011.54658
ArrayForEach         118.77859
#>
