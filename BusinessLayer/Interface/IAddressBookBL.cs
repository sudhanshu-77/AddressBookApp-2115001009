using ModelLayer.DTO;
using ModelLayer.Entity;
using System.Collections.Generic;

namespace BusinessLayer.Interface
{
    public interface IAddressBookBL
    {
        Addresses SaveAddressBookBL(AddressEntity addressEntity);
        Task<AddressEntity?> GetAddressBookByIdBL(int id, string? email);
        Task<List<Addresses>> GetAllAddressBooksBL(string? email);
        Task<Addresses> EditAddressBookBL(string? email, int id, AddressEntity addressEntity);
        bool DeleteAddressBookBL(string? email, int id);
    }
}
