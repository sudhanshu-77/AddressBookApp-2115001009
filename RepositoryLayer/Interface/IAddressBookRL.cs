using ModelLayer.DTO;
using ModelLayer.Entity;
using System.Collections.Generic;

namespace RepositoryLayer.Interface
{
    public interface IAddressBookRL
    {
        Addresses SaveAddressBookRL(AddressEntity addressEntity);
        Task<AddressEntity?> GetAddressBookByIdRL(int id, string? email);
        Task<List<Addresses>> GetAllAddressBooksRL(string? email);
        Task<Addresses> EditAddressBookRL(string? email, int id, AddressEntity addressEntity);
        bool DeleteAddressBookRL(string? email, int id);
    }
}
