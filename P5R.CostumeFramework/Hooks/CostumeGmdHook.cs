using BGME.Framework.Interfaces;
using P5R.CostumeFramework.Configuration;
using P5R.CostumeFramework.Costumes;
using P5R.CostumeFramework.Models;
using p5rpc.lib.interfaces;
using Reloaded.Hooks.Definitions;
using Reloaded.Hooks.Definitions.Enums;
using Reloaded.Hooks.Definitions.X64;
using Reloaded.Memory.SigScan.ReloadedII.Interfaces;
using System;
using System.Net;
using System.Runtime.InteropServices;

namespace P5R.CostumeFramework.Hooks;

internal unsafe class CostumeGmdHook
{
    [Function(CallingConventions.Microsoft)]
    private delegate void LoadAssetHook(nint param1, uint modelId, uint gmdId, uint param4, int param5);
    private IHook<LoadAssetHook>? loadAssetHook;
    private MultiAsmHook? loadAssetAsmHooks;

    [Function(CallingConventions.Microsoft)]
    private delegate bool LoadCombatAnimationString(nuint reshndField00, uint gapID, nint outPath, uint anim_type);
    private IHook<LoadCombatAnimationString>? _loadCombatAnimationStringHook;

    private readonly nint* gmdFileStrPtr;
    private nint tempGmdStrPtr;

    private readonly IBgmeApi bgme;
    private readonly IP5RLib p5rLib;
    private readonly Config config;
    private readonly CostumeRegistry costumes;
    private readonly EquippedItemHook equippedItemHook;

    public CostumeGmdHook(
        IStartupScanner scanner,
        IReloadedHooks hooks,
        IBgmeApi bgme,
        IP5RLib p5RLib,
        Config config,
        CostumeRegistry costumes,
        EquippedItemHook equippedItemHook)
    {
        this.bgme = bgme;
        this.p5rLib = p5RLib;
        this.config = config;
        this.costumes = costumes;
        this.equippedItemHook = equippedItemHook;

        this.gmdFileStrPtr = (nint*)Marshal.AllocHGlobal(sizeof(nint));
        scanner.Scan("Load Asset Function", "48 83 EC 38 8B 44 24 ?? 44 8B D2", result =>
        {
            this.loadAssetHook = hooks.CreateHook<LoadAssetHook>(this.LoadAssetImpl, result).Activate();

            var patch = new string[]
            {
                "use64",
                $"mov rdx, {(nint)this.gmdFileStrPtr}",
                "mov rdx, [rdx]"
            };


            var assetRedirectHooks = new List<IAsmHook>
            {
                hooks.CreateAsmHook(
                patch,
                result + 0x4A,
                AsmHookBehaviour.DoNotExecuteOriginal),

                hooks.CreateAsmHook(
                patch,
                result + 0xDF,
                AsmHookBehaviour.DoNotExecuteOriginal)
            };

            var baseWeaponRedirct = result + 0x2D6;
            foreach (var type in Enum.GetValues<WeaponType>())
            {
                var weaponRedirect = baseWeaponRedirct + ((int)type * 0x1C);
                assetRedirectHooks.Add(hooks.CreateAsmHook(patch, weaponRedirect, AsmHookBehaviour.DoNotExecuteOriginal));
            }

            this.loadAssetAsmHooks = new(assetRedirectHooks.ToArray());
            this.loadAssetAsmHooks.Activate().Disable();
        });

        scanner.Scan("Load Combat Animation Files", "E8 ?? ?? ?? ?? 4C 8B C3 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 48 89 83 ?? ?? ?? ?? 48 8B B4 24 ?? ?? ?? ??", result =>
        {
            // CALL -> Thunk -> Function
            var funcAddress = GetGlobalAddress(result + 1);
            funcAddress = GetGlobalAddress((nint)(funcAddress + 1));

            this._loadCombatAnimationStringHook = hooks.CreateHook<LoadCombatAnimationString>(this.LoadCombatAnimationStringImpl, (long)funcAddress).Activate();
        });
    }

    private void LoadAssetImpl(nint param1, uint modelId, uint gmdId, uint param4, int param5)
    {
        if (param5 == 1 || param5 == 2 || param5 == 4)
        {
            if ( 10 >= modelId ) this.RedirectCostumeGmd(param1, (Character)modelId, gmdId, param4, param5);
        }
        else if (param5 == 14)
        {
            this.RedirectWeaponGmd(param1, modelId, (WeaponType)gmdId, param4, param5);
        }
        else
        {
            this.ClearAssetRedirect();
        }

        this.loadAssetHook?.OriginalFunction(param1, modelId, gmdId, param4, param5);
        this.ClearAssetRedirect();
    }

    private bool LoadCombatAnimationStringImpl(nuint reshndField00, uint gapID, nint outPath, uint anim_type)
    {
        bool result = _loadCombatAnimationStringHook.OriginalFunction(reshndField00, gapID, outPath, anim_type);

        nuint uVar1 = reshndField00 >> 0x3a;

        if (-1 < (int)anim_type)
        {
            uVar1 = anim_type;
        }

        var charID = (Character)((reshndField00 >> 0x14) & 0xffff);

        if ((int)charID <= 10)
        {
            string target_file = Marshal.PtrToStringAnsi(outPath);

            if (anim_type == 1)
            {
                var outptr = this.RedirectCombatGAPFile(charID, gapID);

                Log.Verbose($"Checking Combat GAP {gapID} for {charID} at {target_file}");

                if (outptr != String.Empty)
                {
                    ReplaceFilePathWithMod(outPath, outptr);
                    result = true;
                    Log.Information($"{charID}: Successfully redirected combat GAP");
                }
            }
        }

        return result;
    }

    private void RedirectWeaponGmd(nint param1, uint modelId, WeaponType weaponType, uint param4, int param5)
    {
        var character = (Character)((modelId / 100 % 10) + 1);
        var outfitItemId = this.p5rLib.GET_EQUIP(character, EquipSlot.Costume);
        //var weaponItemId = this.p5rLib.GET_EQUIP(character, EquipSlot.Melee);

        Log.Debug($"Weapon GMD: {param1} || {character} || {modelId} || {weaponType} || {param4} || {param5}");
        if (this.costumes.TryGetCostume(outfitItemId, out var costume))
        {
            switch (weaponType)
            {
                case WeaponType.Melee:
                    this.SetConditionalRedirect(character, costume.WeaponBindPath);
                    break;
                case WeaponType.Melee_R:
                    this.SetConditionalRedirect(character, costume.WeaponRBindPath);
                    break;
                case WeaponType.Melee_L:
                    this.SetConditionalRedirect(character, costume.WeaponLBindPath);
                    break;
                case WeaponType.Ranged:
                    this.SetConditionalRedirect(character, costume.RangedBindPath);
                    break;
                case WeaponType.Ranged_R:
                    this.SetConditionalRedirect(character, costume.RangedRBindPath);
                    break;
                case WeaponType.Ranged_L:
                    this.SetConditionalRedirect(character, costume.RangedLBindPath);
                    break;
                default:
                    break;
            }
        }
    }

    private void RedirectCostumeGmd(nint param1, Character character, uint gmdId, uint param4, int param5)
    {
        var outfitItemId = this.p5rLib.GET_EQUIP(character, EquipSlot.Costume);
        var outfitId = this.GetOutfitId(outfitItemId);
        var outfitSet = (CostumeSet)VirtualOutfitsSection.GetOutfitSetId(outfitItemId);

        if (Enum.IsDefined(character))
        {
            Log.Debug($"GMD: {param1} || {character} || {gmdId} || {param4} || {param5}");
            Log.Debug($"{character} || Item ID: {outfitItemId} || Outfit ID: {outfitId} || Outfit Set: {outfitSet}");
        }
        else
        {
            Log.Verbose($"GMD: {param1} || {character} || {gmdId} || {param4} || {param5}");
        }

        if (IsOutfitModelId((int)gmdId)
            && this.costumes.TryGetCostume(outfitItemId, out var costume)
            && costume.GmdBindPath != null)
        {
            this.SetAssetRedirect(costume.GmdBindPath);
            Log.Verbose($"{character}: redirected {outfitSet} GMD to {costume.GmdBindPath}");
        }
        else Log.Verbose($"No redirect match for {character} in {outfitSet}");
    }

    private string RedirectCombatGAPFile(Character character, uint gapID)
    {
        string result = String.Empty;

        var outfitItemId = this.p5rLib.GET_EQUIP(character, EquipSlot.Costume);
        var gmdId = this.GetCostumeModelId(outfitItemId);
        var outfitId = this.GetOutfitId(outfitItemId);
        var outfitSet = (CostumeSet)VirtualOutfitsSection.GetOutfitSetId(outfitItemId);

        if (IsOutfitModelId((int)gmdId)
            && this.costumes.TryGetCostume(outfitItemId, out var costume))
        {
            if (gapID == 51)
            {
                if (costume.CombatGAP_51_BindPath != null)
                {
                    result = costume.CombatGAP_51_BindPath;
                    Log.Verbose($"{character}: redirected {outfitSet} Combat GAP 51 to {costume.CombatGAP_51_BindPath}");
                }
            }
            else if (gapID == 52)
            {
                if (costume.CombatGAP_52_BindPath != null)
                {
                    result = costume.CombatGAP_52_BindPath;
                    Log.Verbose($"{character}: redirected {outfitSet} Combat GAP 52 to {costume.CombatGAP_52_BindPath}");
                }
            }
        }
        else Log.Verbose($"No redirect match for {character} in {outfitSet}");

        return result;
    }

    private void SetAssetRedirect(string redirectPath)
    {
        this.tempGmdStrPtr = StringsCache.GetStringPtr(redirectPath);
        *this.gmdFileStrPtr = this.tempGmdStrPtr;
        this.loadAssetAsmHooks!.Enable();
    }

    private void ClearAssetRedirect()
    {
        this.tempGmdStrPtr = 0;
        this.loadAssetAsmHooks!.Disable();
    }

    private bool IsOutfitModelId(int modelId)
        => modelId == 51
        || modelId == 52
        || (modelId >= 151 && modelId < 200)
        || (this.config.OverworldCostumes && modelId != 48);

    private int GetOutfitId(int itemId) => itemId - 0x7000;

    private int GetCostumeModelId(int equipmentId)
        => VirtualOutfitsSection.GetOutfitSetId(equipmentId) + 150;

    private void SetConditionalRedirect(Character character, string? redirectPath)
    {
        if (redirectPath != null)
        {
            this.SetAssetRedirect(redirectPath);
            Log.Debug($"Weapon GMD redirected: {character} || {redirectPath}");
        }
    }

    private unsafe nuint GetGlobalAddress(nint ptrAddress)
    {
        return (nuint)((*(int*)ptrAddress) + ptrAddress + 4);
    }

    unsafe static int ReplaceFilePathWithMod(nint target, string newString)
    {
        var strBuffer = Marshal.StringToHGlobalAnsi(newString);

        Buffer.MemoryCopy((void*)strBuffer, (void*)target, newString.Length + 1, newString.Length + 1);

        Marshal.FreeHGlobal(strBuffer);

        return newString.Length + 1;
    }
}
